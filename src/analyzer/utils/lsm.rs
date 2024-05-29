use crate::AnalyzerInterface::TCPStream;

pub enum LSMAction {
    Pause,
    Next,
    Reset,
    Cancel,
}

impl PartialEq for LSMAction {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (LSMAction::Next, LSMAction::Next)
            | (LSMAction::Pause, LSMAction::Pause)
            | (LSMAction::Reset, LSMAction::Reset)
            | (LSMAction::Cancel, LSMAction::Cancel) => true,
            _ => false,
        }
    }
}
pub struct LineStateMachine<T: TCPStream> {
    steps: Vec<Box<dyn FnMut(&mut T) -> LSMAction>>,
    index: usize,
    cancelled: bool,
}

pub fn LSMRun<T: TCPStream>(lsm: &mut LineStateMachine<T>, stream: &mut T) -> (bool, bool) {
    if lsm.index >= lsm.steps.len() {
        return (lsm.cancelled, true);
    }

    let mut actions = lsm.steps.iter_mut().skip(lsm.index);

    while let Some(action) = actions.next() {
        match action(stream) {
            LSMAction::Pause => return (false, false),
            LSMAction::Next => lsm.index += 1,
            LSMAction::Reset => lsm.index = 0,
            LSMAction::Cancel => {
                lsm.cancelled = true;
                return (true, true);
            }
        }
    }
    (false, true)
}

impl<T: TCPStream> LineStateMachine<T> {
    pub fn new(steps: Vec<Box<dyn FnMut(&mut T) -> LSMAction>>) -> Self {
        LineStateMachine {
            steps,
            index: 0,
            cancelled: false,
        }
    }

    pub fn reset(&mut self) {
        self.index = 0;
        self.cancelled = false;
    }
}
