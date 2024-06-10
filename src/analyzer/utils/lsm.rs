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

pub struct LineStateMachine<T> {
    steps: Vec<Box<dyn FnMut(&mut T) -> LSMAction>>,
    index: usize,
    cancelled: bool,
}

impl<T> LineStateMachine<T> {
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

    pub fn lsm_run(&mut self, stream: &mut T) -> (bool, bool) {
        if self.index >= self.steps.len() {
            return (self.cancelled, true);
        }

        let mut actions = self.steps.iter_mut().skip(self.index);

        while let Some(action) = actions.next() {
            match action(stream) {
                LSMAction::Pause => return (false, false),
                LSMAction::Next => self.index += 1,
                LSMAction::Reset => self.index = 0,
                LSMAction::Cancel => {
                    self.cancelled = true;
                    return (true, true);
                }
            }
        }
        (false, true)
    }
}
