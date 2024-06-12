use crate::AnalyzerInterface::PropMap;
use crate::ByteBuffer::ByteBuffer;

pub enum LSMAction {
    Pause,
    Next,
    Reset,
    Cancel,
}

pub struct LSMContext<'a> {
    pub buf: &'a mut ByteBuffer,
    pub done_flag: &'a mut bool,
    pub update_flag: &'a mut bool,
    pub map: &'a mut PropMap,
    pub msg_len: &'a mut usize,
}

impl<'a> LSMContext<'a> {
    pub fn new(
        buf: &'a mut ByteBuffer,
        done_flag: &'a mut bool,
        update_flag: &'a mut bool,
        map: &'a mut PropMap,
        msg_len: &'a mut usize,
    ) -> LSMContext<'a> {
        Self {
            buf,
            done_flag,
            update_flag,
            map,
            msg_len,
        }
    }
}

impl PartialEq for LSMAction {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (LSMAction::Next, LSMAction::Next)
                | (LSMAction::Pause, LSMAction::Pause)
                | (LSMAction::Reset, LSMAction::Reset)
                | (LSMAction::Cancel, LSMAction::Cancel)
        )
    }
}

pub struct LineStateMachine {
    steps: Vec<Box<dyn FnMut(&mut LSMContext) -> LSMAction>>,
    index: usize,
    cancelled: bool,
}

impl LineStateMachine {
    pub fn new(steps: Vec<Box<dyn FnMut(&mut LSMContext) -> LSMAction>>) -> Self {
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

    pub fn lsm_run(&mut self, ctx: &mut LSMContext) -> (bool, bool) {
        while self.index < self.steps.len() {
            match (self.steps[self.index])(ctx) {
                LSMAction::Pause => return (false, false),
                LSMAction::Next => self.index += 1,
                LSMAction::Reset => self.reset(),
                LSMAction::Cancel => {
                    self.cancelled = true;
                    return (true, true);
                }
            }
        }
        (self.cancelled, true)
    }
}
