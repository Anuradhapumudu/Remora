//! What a person types at the host: short prompt numbers and the commands
//! that use them (walkthrough finding F-UX1, 2026-10-20).
//!
//! The protocol's session IDs are 64-bit random numbers — fine for the
//! code, unusable for a person who must read one and type it back. The host
//! CLI shows **prompt numbers** instead: 1, 2, 3, … counted per run.
//!
//! **A number is never reused within a run.** Reuse would be a security bug,
//! not just a confusing one: if prompt 1 is withdrawn and a new viewer then
//! got number 1, an `accept 1` typed for the old prompt would approve the new
//! viewer. Approval stays bound to the session *and* the safety code shown
//! on its prompt (A22); the number only selects which one.

use std::collections::BTreeMap;

/// Prompt numbers mapped to whatever the app keeps per session.
#[derive(Debug)]
pub struct SessionBook<T> {
    last: u64,
    entries: BTreeMap<u64, T>,
}

impl<T> Default for SessionBook<T> {
    fn default() -> Self {
        Self {
            last: 0,
            entries: BTreeMap::new(),
        }
    }
}

impl<T> SessionBook<T> {
    /// An empty book; the first number handed out is 1.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores `value` under the next number (never one used before in this
    /// book) and returns that number.
    pub fn insert(&mut self, value: T) -> u64 {
        // 2^64 prompts cannot happen in one run; saturating keeps it panic-free.
        self.last = self.last.saturating_add(1);
        self.entries.insert(self.last, value);
        self.last
    }

    /// The entry with number `n`.
    pub fn get(&self, n: u64) -> Option<&T> {
        self.entries.get(&n)
    }

    /// The entry with number `n`, mutably.
    pub fn get_mut(&mut self, n: u64) -> Option<&mut T> {
        self.entries.get_mut(&n)
    }

    /// Removes and returns the entry with number `n`.
    pub fn remove(&mut self, n: u64) -> Option<T> {
        self.entries.remove(&n)
    }

    /// The number of the first entry for which `pred` holds.
    pub fn find(&self, mut pred: impl FnMut(&T) -> bool) -> Option<u64> {
        self.entries.iter().find_map(|(n, v)| pred(v).then_some(*n))
    }

    /// Numbers of the entries for which `pred` holds, in increasing order.
    pub fn numbers_where(&self, mut pred: impl FnMut(&T) -> bool) -> Vec<u64> {
        self.entries
            .iter()
            .filter_map(|(n, v)| pred(v).then_some(*n))
            .collect()
    }
}

/// A command typed at the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostCommand {
    /// An empty line.
    Nothing,
    /// `quit`.
    Quit,
    /// `accept <n>`.
    Accept(u64),
    /// `deny <n>`.
    Deny(u64),
    /// `disconnect <n>`.
    Disconnect(u64),
}

/// Why a typed line is not a command. Every case is shown to the person:
/// nothing typed is ever ignored silently.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommandError {
    /// Not one of the commands.
    #[error("unknown command {0:?} - commands: accept <n>, deny <n>, disconnect <n>, quit")]
    Unknown(String),
    /// `accept` / `deny` / `disconnect` without a number.
    #[error("'{0}' needs the prompt number shown on screen, e.g. '{0} 1'")]
    MissingNumber(&'static str),
    /// The argument is not a number.
    #[error(
        "{arg:?} is not a prompt number - type the number shown after 'prompt', e.g. '{cmd} 1'"
    )]
    NotANumber {
        /// The command typed.
        cmd: &'static str,
        /// What followed it.
        arg: String,
    },
    /// Something after the number.
    #[error("'{0}' takes exactly one prompt number")]
    TooManyWords(&'static str),
}

/// Parses one line typed at the host.
pub fn parse_host_command(line: &str) -> Result<HostCommand, CommandError> {
    let mut words = line.split_whitespace();
    let Some(first) = words.next() else {
        return Ok(HostCommand::Nothing);
    };
    let (cmd, make): (&'static str, fn(u64) -> HostCommand) = match first {
        "quit" if words.next().is_none() => return Ok(HostCommand::Quit),
        "accept" => ("accept", HostCommand::Accept),
        "deny" => ("deny", HostCommand::Deny),
        "disconnect" => ("disconnect", HostCommand::Disconnect),
        _ => return Err(CommandError::Unknown(line.trim().to_owned())),
    };
    let arg = words.next().ok_or(CommandError::MissingNumber(cmd))?;
    if words.next().is_some() {
        return Err(CommandError::TooManyWords(cmd));
    }
    let n = arg.parse::<u64>().map_err(|_| CommandError::NotANumber {
        cmd,
        arg: arg.to_owned(),
    })?;
    Ok(make(n))
}

/// The message for a number that matches no prompt, listing what is open
/// so a typo is obvious.
pub fn no_such_prompt(n: u64, open: &[u64]) -> String {
    if open.is_empty() {
        format!("no pending prompt {n} - there are no prompts waiting")
    } else {
        let list: Vec<String> = open.iter().map(u64::to_string).collect();
        format!("no pending prompt {n} - waiting: {}", list.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_start_at_one_and_count_up() {
        let mut b = SessionBook::new();
        assert_eq!(b.insert('a'), 1);
        assert_eq!(b.insert('b'), 2);
        assert_eq!(b.get(1), Some(&'a'));
        assert_eq!(b.get(2), Some(&'b'));
        assert_eq!(b.get(3), None);
    }

    #[test]
    fn a_number_is_never_reused_after_its_entry_is_removed() {
        // The security property: a stale 'accept 1' must never reach a
        // different viewer.
        let mut b = SessionBook::new();
        let first = b.insert("old viewer");
        assert_eq!(b.remove(first), Some("old viewer"));
        let second = b.insert("new viewer");
        assert_ne!(first, second);
        assert_eq!(b.get(first), None);
        // Also after everything was removed and the book is empty again.
        b.remove(second);
        assert_eq!(b.insert("third"), 3);
    }

    #[test]
    fn find_and_numbers_where_select_by_content() {
        let mut b = SessionBook::new();
        b.insert(10);
        b.insert(20);
        b.insert(30);
        b.remove(2);
        assert_eq!(b.find(|v| *v == 30), Some(3));
        assert_eq!(b.find(|v| *v == 20), None);
        assert_eq!(b.numbers_where(|v| *v >= 10), vec![1, 3]);
        assert_eq!(b.numbers_where(|v| *v > 10), vec![3]);
        if let Some(v) = b.get_mut(1) {
            *v = 11;
        }
        assert_eq!(b.get(1), Some(&11));
    }

    #[test]
    fn commands_parse() {
        assert_eq!(parse_host_command(""), Ok(HostCommand::Nothing));
        assert_eq!(parse_host_command("   "), Ok(HostCommand::Nothing));
        assert_eq!(parse_host_command("quit"), Ok(HostCommand::Quit));
        assert_eq!(parse_host_command("accept 1"), Ok(HostCommand::Accept(1)));
        assert_eq!(parse_host_command(" deny  2 "), Ok(HostCommand::Deny(2)));
        assert_eq!(
            parse_host_command("disconnect 3"),
            Ok(HostCommand::Disconnect(3))
        );
    }

    #[test]
    fn every_mistake_is_an_explicit_error() {
        assert_eq!(
            parse_host_command("accept"),
            Err(CommandError::MissingNumber("accept"))
        );
        assert_eq!(
            parse_host_command("deny x1"),
            Err(CommandError::NotANumber {
                cmd: "deny",
                arg: "x1".into()
            })
        );
        assert_eq!(
            parse_host_command("accept 1 2"),
            Err(CommandError::TooManyWords("accept"))
        );
        assert_eq!(
            parse_host_command("quit now"),
            Err(CommandError::Unknown("quit now".into()))
        );
        assert_eq!(
            parse_host_command("launch-rockets"),
            Err(CommandError::Unknown("launch-rockets".into()))
        );
        // The messages say what to type.
        let msg = parse_host_command("accept").unwrap_err().to_string();
        assert!(msg.contains("accept 1"), "{msg}");
        let msg = parse_host_command("accept abc").unwrap_err().to_string();
        assert!(msg.contains("\"abc\"") && msg.contains("accept 1"), "{msg}");
    }

    #[test]
    fn no_such_prompt_lists_what_is_waiting() {
        assert_eq!(
            no_such_prompt(7, &[1, 3]),
            "no pending prompt 7 - waiting: 1, 3"
        );
        assert_eq!(
            no_such_prompt(7, &[]),
            "no pending prompt 7 - there are no prompts waiting"
        );
    }
}
