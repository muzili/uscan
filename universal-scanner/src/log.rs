//! 5 级日志（Fatal..Debug），stderr 输出，任务号前缀。

use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Fatal = 0,
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
}

impl Level {
    pub fn tag(self) -> &'static str {
        match self {
            Level::Fatal => "FATAL",
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
        }
    }
}

/// 输出 stderr，格式 `[{id,4}] {LEVEL}: {msg}`（C# 原格式无 LEVEL 前缀，Rust 增加，spec §8.2）。
#[derive(Debug)]
pub struct Logger {
    level: AtomicU8,
    task_ids: AtomicU32,
}

impl Logger {
    pub fn new(level: Level) -> Self {
        Self {
            level: AtomicU8::new(level as u8),
            task_ids: AtomicU32::new(1),
        }
    }

    pub fn set_level(&self, level: Level) {
        self.level.store(level as u8, Ordering::Relaxed);
    }

    pub fn level(&self) -> Level {
        match self.level.load(Ordering::Relaxed) {
            0 => Level::Fatal,
            1 => Level::Error,
            2 => Level::Warn,
            3 => Level::Info,
            _ => Level::Debug,
        }
    }

    pub fn enabled(&self, level: Level) -> bool {
        level <= self.level()
    }

    /// 为每个 spawn 的接收/长任务分配任务号（C# ManagedThreadId 语义）。
    pub fn next_task_id(&self) -> u32 {
        self.task_ids.fetch_add(1, Ordering::Relaxed)
    }

    pub fn log(&self, level: Level, task_id: u32, msg: &str) {
        if self.enabled(level) {
            eprintln!("[{:4}] {}: {}", task_id, level.tag(), msg);
        }
    }

    pub fn fatal(&self, id: u32, msg: &str) {
        self.log(Level::Fatal, id, msg);
    }
    pub fn error(&self, id: u32, msg: &str) {
        self.log(Level::Error, id, msg);
    }
    pub fn warn(&self, id: u32, msg: &str) {
        self.log(Level::Warn, id, msg);
    }
    pub fn info(&self, id: u32, msg: &str) {
        self.log(Level::Info, id, msg);
    }
    pub fn debug(&self, id: u32, msg: &str) {
        self.log(Level::Debug, id, msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_ordering() {
        assert!(Level::Fatal < Level::Error);
        assert!(Level::Error < Level::Warn);
        assert!(Level::Warn < Level::Info);
        assert!(Level::Info < Level::Debug);
    }

    #[test]
    fn tags() {
        assert_eq!(Level::Fatal.tag(), "FATAL");
        assert_eq!(Level::Debug.tag(), "DEBUG");
    }

    #[test]
    fn gating() {
        let l = Logger::new(Level::Warn);
        // 门限语义同 C#（lineLevel <= level）：Warn 门限下 Error/Fatal/Warn 启用，Info 禁用。
        assert!(l.enabled(Level::Error));
        assert!(l.enabled(Level::Warn));
        assert!(l.enabled(Level::Fatal));
        assert!(!l.enabled(Level::Info));
        l.set_level(Level::Debug);
        assert!(l.enabled(Level::Debug));
    }
}
