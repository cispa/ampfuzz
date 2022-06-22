// Assume it is direct and linear
use super::*;

pub struct AmpFuzz<'a> {
    handler: SearchHandler<'a>,
}

impl<'a> AmpFuzz<'a> {
    pub fn new(handler: SearchHandler<'a>) -> Self {
        Self { handler }
    }

    pub fn run(&mut self) {
        if !config::ENABLE_INPUT_AMP_EXPLORATION {
            self.handler.cond.mark_as_done();
            return;
        }

        let mut buf = self.handler.buf.clone();
        debug!(
            "amp: buf_len: {}, buf: {:x?}",
            buf.len(),
            buf
        );

        // Try all shorter inputs
        while buf.len() > 0 {
            buf.pop();
            self.handler.execute(&buf);
        }

        self.handler.cond.mark_as_done();
    }
}
