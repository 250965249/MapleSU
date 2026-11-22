//! Fixed root-only recovery boundary for Normal mode; no paths or arbitrary commands.

#[derive(Clone, Copy, Debug)]
#[cfg_attr(target_os = "android", derive(clap::ValueEnum))]
pub enum Operation {
    Readiness,
    State,
    On,
    Off,
}

impl Operation {
    const fn name(self) -> &'static str {
        match self {
            Self::Readiness => "readiness",
            Self::State => "state",
            Self::On => "on",
            Self::Off => "off",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    NotRoot,
    ReadFailed,
    WriteFailed,
    ReadbackFailed,
    StateMismatch,
}

impl Failure {
    const fn code(self) -> &'static str {
        match self {
            Self::NotRoot => "NOT_ROOT",
            Self::ReadFailed => "READ_FAILED",
            Self::WriteFailed => "WRITE_FAILED",
            Self::ReadbackFailed => "READBACK_FAILED",
            Self::StateMismatch => "STATE_MISMATCH",
        }
    }
}

pub trait StealthPort {
    type Error;
    fn read(&mut self) -> Result<bool, Self::Error>;
    fn write(&mut self, enabled: bool) -> Result<(), Self::Error>;
}

pub fn execute(
    operation: Operation,
    is_root: bool,
    port: &mut impl StealthPort,
) -> Result<bool, Failure> {
    if !is_root {
        return Err(Failure::NotRoot);
    }
    match operation {
        Operation::State => port.read().map_err(|_| Failure::ReadFailed),
        Operation::On => set_and_verify(true, port),
        Operation::Off => set_and_verify(false, port),
        Operation::Readiness => {
            let current = port.read().map_err(|_| Failure::ReadFailed)?;
            set_and_verify(current, port)
        }
    }
}

fn set_and_verify(enabled: bool, port: &mut impl StealthPort) -> Result<bool, Failure> {
    port.write(enabled).map_err(|_| Failure::WriteFailed)?;
    let actual = port.read().map_err(|_| Failure::ReadbackFailed)?;
    if actual != enabled {
        return Err(Failure::StateMismatch);
    }
    Ok(actual)
}

pub fn receipt(operation: Operation, result: Result<bool, Failure>) -> String {
    let outcome = match result {
        Ok(enabled) => format!("stealth={}", u8::from(enabled)),
        Err(error) => format!("error={}", error.code()),
    };
    format!(
        "MAPLESU_NORMAL_RECOVERY_V1 operation={} {outcome}",
        operation.name()
    )
}

#[cfg(target_os = "android")]
pub fn run(operation: Operation) -> anyhow::Result<()> {
    struct KernelStealth;
    impl StealthPort for KernelStealth {
        type Error = anyhow::Error;
        fn read(&mut self) -> Result<bool, Self::Error> {
            crate::ksucalls::stealth_probe_get()
        }
        fn write(&mut self, enabled: bool) -> Result<(), Self::Error> {
            crate::ksucalls::stealth_probe_set(enabled)
        }
    }

    let is_root = unsafe { libc::getuid() == 0 && libc::geteuid() == 0 };
    let result = execute(operation, is_root, &mut KernelStealth);
    println!("{}", receipt(operation, result));
    result
        .map(|_| ())
        .map_err(|error| anyhow::anyhow!(error.code()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Port {
        state: bool,
        writes: usize,
    }
    impl StealthPort for Port {
        type Error = ();
        fn read(&mut self) -> Result<bool, Self::Error> {
            Ok(self.state)
        }
        fn write(&mut self, value: bool) -> Result<(), Self::Error> {
            self.state = value;
            self.writes += 1;
            Ok(())
        }
    }

    #[test]
    fn state_is_read_only_and_has_a_fixed_receipt() {
        let mut port = Port {
            state: true,
            writes: 0,
        };
        let result = execute(Operation::State, true, &mut port);
        assert_eq!(result, Ok(true));
        assert_eq!(port.writes, 0);
        assert_eq!(
            receipt(Operation::State, result),
            "MAPLESU_NORMAL_RECOVERY_V1 operation=state stealth=1"
        );
    }
    #[test]
    fn readiness_proves_same_value_write_and_readback_without_toggling() {
        for enabled in [false, true] {
            let mut port = Port {
                state: enabled,
                writes: 0,
            };
            assert_eq!(execute(Operation::Readiness, true, &mut port), Ok(enabled));
            assert_eq!(port.state, enabled);
            assert_eq!(port.writes, 1);
        }
    }

    #[test]
    fn on_and_off_confirm_the_requested_kernel_state() {
        let mut port = Port {
            state: false,
            writes: 0,
        };
        assert_eq!(execute(Operation::On, true, &mut port), Ok(true));
        assert_eq!(execute(Operation::Off, true, &mut port), Ok(false));
        assert_eq!(port.writes, 2);
        assert_eq!(
            receipt(Operation::Off, Ok(false)),
            "MAPLESU_NORMAL_RECOVERY_V1 operation=off stealth=0"
        );
    }

    struct FaultPort {
        reads: usize,
        writes: usize,
        fail_read_at: Option<usize>,
        fail_write: bool,
        state: bool,
        ignore_write: bool,
    }
    impl FaultPort {
        fn new() -> Self {
            Self {
                reads: 0,
                writes: 0,
                fail_read_at: None,
                fail_write: false,
                state: false,
                ignore_write: false,
            }
        }
    }
    impl StealthPort for FaultPort {
        type Error = ();
        fn read(&mut self) -> Result<bool, Self::Error> {
            self.reads += 1;
            if self.fail_read_at == Some(self.reads) {
                return Err(());
            }
            Ok(self.state)
        }
        fn write(&mut self, enabled: bool) -> Result<(), Self::Error> {
            self.writes += 1;
            if self.fail_write {
                return Err(());
            }
            if !self.ignore_write {
                self.state = enabled;
            }
            Ok(())
        }
    }

    #[test]
    fn non_root_has_no_kernel_side_effects() {
        for operation in [
            Operation::Readiness,
            Operation::State,
            Operation::On,
            Operation::Off,
        ] {
            let mut port = FaultPort::new();
            assert_eq!(execute(operation, false, &mut port), Err(Failure::NotRoot));
            assert_eq!((port.reads, port.writes), (0, 0));
        }
    }

    #[test]
    fn readiness_read_failure_does_not_write() {
        let mut port = FaultPort::new();
        port.fail_read_at = Some(1);
        assert_eq!(
            execute(Operation::Readiness, true, &mut port),
            Err(Failure::ReadFailed)
        );
        assert_eq!(port.writes, 0);
    }

    #[test]
    fn write_failure_is_not_success_and_has_a_fixed_error_receipt() {
        let mut port = FaultPort::new();
        port.fail_write = true;
        let result = execute(Operation::On, true, &mut port);
        assert_eq!(result, Err(Failure::WriteFailed));
        assert_eq!(port.reads, 0);
        assert_eq!(
            receipt(Operation::On, result),
            "MAPLESU_NORMAL_RECOVERY_V1 operation=on error=WRITE_FAILED"
        );
    }

    #[test]
    fn readiness_readback_failure_is_not_success() {
        let mut port = FaultPort::new();
        port.fail_read_at = Some(2);
        assert_eq!(
            execute(Operation::Readiness, true, &mut port),
            Err(Failure::ReadbackFailed)
        );
        assert_eq!(port.writes, 1);
    }

    #[test]
    fn on_rejects_write_that_did_not_change_kernel_state() {
        let mut port = FaultPort::new();
        port.ignore_write = true;
        assert_eq!(
            execute(Operation::On, true, &mut port),
            Err(Failure::StateMismatch)
        );
    }

    #[test]
    fn off_rejects_write_that_did_not_change_kernel_state() {
        let mut port = FaultPort::new();
        port.state = true;
        port.ignore_write = true;
        assert_eq!(
            execute(Operation::Off, true, &mut port),
            Err(Failure::StateMismatch)
        );
    }
}
