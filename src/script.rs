use std::error::Error;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{Config, DynStream, EXIT_ERROR, EXIT_EXPECT_FAILED, EXIT_LIMIT, Report};

const MAX_SOURCE: u64 = 1024 * 1024;
const MAX_STEPS: usize = 4096;
const MAX_DEPTH: usize = 16;
const MAX_CASES: usize = 128;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document
{
    #[serde(default = "version")]
    version: u32,
    #[serde(default = "default_timeout")]
    step_timeout: f64,
    steps: Vec<RawStep>,
}

fn version() -> u32
{
    1
}
fn default_timeout() -> f64
{
    2.0
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStep
{
    name: Option<String>,
    send_line: Option<String>,
    send: Option<String>,
    send_base64: Option<String>,
    expect: Option<Expectation>,
    expect_eof: Option<bool>,
    shutdown_write: Option<bool>,
    fail: Option<String>,
    timeout: Option<f64>,
    then: Option<Vec<RawStep>>,
    #[serde(rename = "else")]
    otherwise: Option<Vec<RawStep>>,
    on_timeout: Option<Vec<RawStep>>,
    on_eof: Option<Vec<RawStep>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Expectation
{
    Text(String),
    Cases(Vec<RawCase>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCase
{
    text: String,
    #[serde(default)]
    then: Vec<RawStep>,
}

pub struct Script
{
    steps: Vec<Step>,
}

struct Step
{
    name: Option<String>,
    action: Action,
    timeout: Duration,
    then: Vec<Step>,
    otherwise: Option<Vec<Step>>,
    on_timeout: Option<Vec<Step>>,
    on_eof: Option<Vec<Step>>,
}

enum Action
{
    Send(Vec<u8>),
    Expect(Vec<Case>),
    ExpectEof,
    ShutdownWrite,
    Fail(String),
}

impl Action
{
    fn name(&self) -> &'static str
    {
        match self
        {
            Self::Send(_) => "send",
            Self::Expect(_) => "expect",
            Self::ExpectEof => "expect_eof",
            Self::ShutdownWrite => "shutdown_write",
            Self::Fail(_) => "fail",
        }
    }
}

struct Case
{
    text: Vec<u8>,
    then: Vec<Step>,
}

pub async fn read(path: &Path) -> Result<String, Box<dyn Error>>
{
    let mut source = String::new();
    tokio::fs::File::open(path)
        .await?
        .take(MAX_SOURCE + 1)
        .read_to_string(&mut source)
        .await?;
    Ok(source)
}

pub fn parse(source: &str, path: &Path, eol: &[u8]) -> Result<Script, String>
{
    if source.len() as u64 > MAX_SOURCE
    {
        return Err("script exceeds 1 MiB".into());
    }
    let document: Document = match path.extension().and_then(|ext| ext.to_str())
    {
        Some(ext) if ext.eq_ignore_ascii_case("json") =>
        {
            serde_json::from_str(source).map_err(|err| err.to_string())?
        }
        Some(ext) if ext.eq_ignore_ascii_case("toml") =>
        {
            toml::from_str(source).map_err(|err| err.to_string())?
        }
        _ => return Err("script filename must end in .json or .toml".into()),
    };
    if document.version != 1
    {
        return Err("unsupported script version; expected 1".into());
    }
    if document.steps.is_empty()
    {
        return Err("script steps must not be empty".into());
    }
    let default = seconds(document.step_timeout)?;
    let mut count = 0;
    let steps = compile(document.steps, default, eol, 0, &mut count, "steps")?;
    Ok(Script { steps })
}

fn seconds(value: f64) -> Result<Duration, String>
{
    Duration::try_from_secs_f64(value)
        .ok()
        .filter(|d| !d.is_zero())
        .ok_or_else(|| "step timeout must be finite and positive".into())
}

fn compile(
    raw: Vec<RawStep>,
    default: Duration,
    eol: &[u8],
    depth: usize,
    count: &mut usize,
    prefix: &str,
) -> Result<Vec<Step>, String>
{
    if raw.is_empty()
    {
        return Ok(Vec::new());
    }
    if depth > MAX_DEPTH
    {
        return Err("script nesting exceeds 16 levels".into());
    }
    let mut steps = Vec::new();
    for (index, raw) in raw.into_iter().enumerate()
    {
        *count += 1;
        if *count > MAX_STEPS
        {
            return Err("script exceeds 4096 steps".into());
        }
        let path = format!("{prefix}[{index}]");
        let actions = [
            raw.send_line.is_some(),
            raw.send.is_some(),
            raw.send_base64.is_some(),
            raw.expect.is_some(),
            raw.expect_eof.is_some(),
            raw.shutdown_write.is_some(),
            raw.fail.is_some(),
        ];
        if actions.into_iter().filter(|present| *present).count() != 1
        {
            return Err(format!("{path}: each step requires exactly one action"));
        }
        let expecting = raw.expect.is_some() || raw.expect_eof.is_some();
        if !expecting
            && (raw.then.is_some()
                || raw.otherwise.is_some()
                || raw.on_timeout.is_some()
                || raw.on_eof.is_some())
        {
            return Err(format!("{path}: branches are only valid on expectation steps"));
        }
        let timeout = raw.timeout.map(seconds).transpose()?.unwrap_or(default);
        let action = if let Some(line) = raw.send_line
        {
            let mut bytes = line.into_bytes();
            bytes.extend_from_slice(eol);
            Action::Send(bytes)
        }
        else if let Some(text) = raw.send
        {
            Action::Send(text.into_bytes())
        }
        else if let Some(encoded) = raw.send_base64
        {
            Action::Send(
                STANDARD
                    .decode(encoded)
                    .map_err(|err| format!("{path}: invalid base64: {err}"))?,
            )
        }
        else if let Some(expectation) = raw.expect
        {
            let cases = match expectation
            {
                Expectation::Text(text) => vec![RawCase {
                    text,
                    then: Vec::new(),
                }],
                Expectation::Cases(cases) => cases,
            };
            if cases.is_empty() || cases.len() > MAX_CASES
            {
                return Err(format!("{path}: expect requires 1 to 128 cases"));
            }
            let mut compiled = Vec::new();
            for (index, case) in cases.into_iter().enumerate()
            {
                if case.text.is_empty()
                {
                    return Err(format!("{path}: expect text must not be empty"));
                }
                let then = compile(
                    case.then,
                    default,
                    eol,
                    depth + 1,
                    count,
                    &format!("{path}.expect[{index}].then"),
                )?;
                compiled.push(Case {
                    text: case.text.into_bytes(),
                    then,
                });
            }
            Action::Expect(compiled)
        }
        else if let Some(enabled) = raw.expect_eof
        {
            if !enabled
            {
                return Err(format!("{path}: expect_eof must be true"));
            }
            Action::ExpectEof
        }
        else if let Some(enabled) = raw.shutdown_write
        {
            if !enabled
            {
                return Err(format!("{path}: shutdown_write must be true"));
            }
            Action::ShutdownWrite
        }
        else
        {
            Action::Fail(raw.fail.expect("validated action"))
        };
        let mut branch = |raw: Option<Vec<RawStep>>, label: &str| {
            raw.map(|raw| compile(raw, default, eol, depth + 1, count, &format!("{path}.{label}")))
                .transpose()
        };
        let then = branch(raw.then, "then")?.unwrap_or_default();
        let otherwise = branch(raw.otherwise, "else")?;
        let on_timeout = branch(raw.on_timeout, "on_timeout")?;
        let on_eof = branch(raw.on_eof, "on_eof")?;
        steps.push(Step {
            name: raw.name,
            action,
            timeout,
            then,
            otherwise,
            on_timeout,
            on_eof,
        });
    }
    Ok(steps)
}

pub async fn run(
    script: &Script,
    stream: &mut DynStream,
    config: &Config,
    report: &mut Report,
) -> Result<u8, Box<dyn Error>>
{
    let mut runner = Runner {
        stream,
        config,
        report,
        pending: Vec::new(),
        pending_start: 0,
        eof: false,
        write_closed: false,
    };
    let code = runner
        .sequence(&script.steps, "steps".into())
        .await?
        .unwrap_or_else(|| runner.report.finish(0, "script_completed"));
    let _ = runner.stream.shutdown().await;
    if code != 0
        && !config.json
        && let Some(error) = &runner.report.error
    {
        eprintln!("Error: {error}");
    }
    Ok(code)
}

struct Runner<'a>
{
    stream: &'a mut DynStream,
    config: &'a Config,
    report: &'a mut Report,
    pending: Vec<u8>,
    pending_start: u64,
    eof: bool,
    write_closed: bool,
}

enum Event
{
    Done(&'static str),
    Matched(Option<(usize, u64, u64)>),
    Timeout(&'static str),
    Eof,
    Limit,
}

type Flow = Result<Option<u8>, Box<dyn Error>>;

impl Runner<'_>
{
    fn sequence<'a>(
        &'a mut self,
        steps: &'a [Step],
        prefix: String,
    ) -> Pin<Box<dyn Future<Output = Flow> + 'a>>
    {
        Box::pin(async move {
            for (index, step) in steps.iter().enumerate()
            {
                tokio::task::yield_now().await;
                if let Some(code) = self.step(step, &format!("{prefix}[{index}]")).await?
                {
                    return Ok(Some(code));
                }
            }
            Ok(None)
        })
    }

    async fn step(&mut self, step: &Step, path: &str) -> Flow
    {
        self.report
            .begin_step(path, step.name.as_deref(), step.action.name());
        if let Action::Fail(message) = &step.action
        {
            self.report.phase = "script";
            self.report.error = Some(format!("{path}: {message}"));
            return Ok(Some(self.report.finish(EXIT_EXPECT_FAILED, "script_failure")));
        }
        let event = match tokio::time::timeout(step.timeout, self.perform(&step.action)).await
        {
            Ok(result) => result?,
            Err(_) => Event::Timeout("step_timeout"),
        };
        match event
        {
            Event::Done(reason) => self.report.end_step(reason, 0, false, None),
            Event::Matched(matched) =>
            {
                self.report.matched = true;
                self.report.end_step("expect_matched", 0, false, matched);
                if let (Action::Expect(cases), Some((index, _, _))) = (&step.action, matched)
                    && let Some(code) = self
                        .sequence(&cases[index].then, format!("{path}.expect[{index}].then"))
                        .await?
                {
                    return Ok(Some(code));
                }
                return self.sequence(&step.then, format!("{path}.then")).await;
            }
            Event::Timeout(_) | Event::Eof
                if matches!(step.action, Action::Expect(_) | Action::ExpectEof)
                    && self.report.phase == "read" =>
            {
                let (reason, handler, label) = match event
                {
                    Event::Timeout(reason) if step.on_timeout.is_some() =>
                    {
                        (reason, step.on_timeout.as_ref(), "on_timeout")
                    }
                    Event::Timeout(reason) => (reason, step.otherwise.as_ref(), "else"),
                    _ if step.on_eof.is_some() => ("eof", step.on_eof.as_ref(), "on_eof"),
                    _ => ("eof", step.otherwise.as_ref(), "else"),
                };
                self.report.matched = false;
                self.report
                    .end_step(reason, EXIT_EXPECT_FAILED, handler.is_some(), None);
                if let Some(handler) = handler
                {
                    return self.sequence(handler, format!("{path}.{label}")).await;
                }
                self.report.error = Some(format!("{path}: expectation ended with {reason}"));
                return Ok(Some(self.report.finish(EXIT_EXPECT_FAILED, reason)));
            }
            Event::Limit => return Ok(Some(self.report.finish(EXIT_LIMIT, "max_bytes"))),
            Event::Timeout(reason) =>
            {
                self.report.error = Some(format!("{path}: {reason} during {}", self.report.phase));
                return Ok(Some(self.report.finish(EXIT_ERROR, reason)));
            }
            Event::Eof => unreachable!("EOF only arises while expecting"),
        }
        Ok(None)
    }

    async fn perform(&mut self, action: &Action) -> Result<Event, Box<dyn Error>>
    {
        match action
        {
            Action::Send(bytes) =>
            {
                self.report.phase = "write";
                if self.write_closed
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "sending side is closed",
                    )
                    .into());
                }
                let mut remaining = bytes.as_slice();
                while !remaining.is_empty()
                {
                    let n = self.stream.write(remaining).await?;
                    if n == 0
                    {
                        return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
                    }
                    self.report.bytes_sent += n as u64;
                    remaining = &remaining[n..];
                }
                self.stream.flush().await?;
                return Ok(Event::Done("sent"));
            }
            Action::ShutdownWrite =>
            {
                self.report.phase = "write";
                self.stream.shutdown().await?;
                self.write_closed = true;
                return Ok(Event::Done("write_shutdown"));
            }
            Action::Fail(_) => unreachable!("fail is handled before I/O"),
            _ =>
            {}
        }
        self.report.phase = "read";
        self.report.matched = false;
        let mut scanned = 0usize;
        loop
        {
            if let Action::Expect(cases) = action
            {
                let found = cases
                    .iter()
                    .enumerate()
                    .filter_map(|(index, case)| {
                        let start = scanned.saturating_sub(case.text.len() - 1);
                        memchr::memmem::find(&self.pending[start..], &case.text)
                            .map(|offset| (index, start + offset, start + offset + case.text.len()))
                    })
                    .min_by_key(|(index, _, end)| (*end, *index));
                if let Some((index, start, end)) = found
                {
                    let matched =
                        (index, self.pending_start + start as u64, self.pending_start + end as u64);
                    self.pending.drain(..end);
                    self.pending_start += end as u64;
                    return Ok(Event::Matched(Some(matched)));
                }
            }
            scanned = self.pending.len();
            if self.eof
            {
                if matches!(action, Action::ExpectEof)
                {
                    self.pending_start += self.pending.len() as u64;
                    self.pending.clear();
                    return Ok(Event::Matched(None));
                }
                return Ok(Event::Eof);
            }
            let mut bytes = [0u8; 8192];
            let remaining = self.config.max_bytes.unwrap_or(u64::MAX) - self.report.bytes_received;
            let size = remaining.min(bytes.len() as u64) as usize;
            if size == 0
            {
                return Ok(Event::Limit);
            }
            let result = match self.config.idle_timeout
            {
                Some(idle) =>
                {
                    match tokio::time::timeout(idle, self.stream.read(&mut bytes[..size])).await
                    {
                        Ok(result) => result,
                        Err(_) => return Ok(Event::Timeout("idle_timeout")),
                    }
                }
                None => self.stream.read(&mut bytes[..size]).await,
            };
            let n = result?;
            if n == 0
            {
                self.eof = true;
                continue;
            }
            self.report.bytes_received += n as u64;
            self.pending.extend_from_slice(&bytes[..n]);
            if self.config.json
            {
                self.report.output.extend_from_slice(&bytes[..n]);
            }
            else
            {
                self.report.phase = "output";
                let mut output = tokio::io::stdout();
                output.write_all(&bytes[..n]).await?;
                output.flush().await?;
                self.report.phase = "read";
            }
        }
    }
}
