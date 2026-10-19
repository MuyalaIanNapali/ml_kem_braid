use crate::{EpochSecret, Error};
use crate::ml_kem_braid::messages::Message;
use crate::ml_kem_braid::states::State;

pub struct SendResult {
    pub msg: Message,
    pub key: Option<EpochSecret>,
    pub state: State,
}
impl State {
    pub fn send(self) -> Result<SendResult, Error> {
        match self {
            State::KeyUnsampled(state) => {
                let (new_state, msg, _epoch, key) = state.send();
                Ok(SendResult {
                    msg,
                    key,
                    state: new_state,
                })
            }
            State::KeySampled(mut state) => {
                let (msg, _epoch, key) = state.send_header();

                Ok(SendResult {
                    msg,
                    key,
                    state: State::KeySampled(state),
                })
            }
            
            State::HeaderSent(mut state) => {
                let (msg, _epoch, key) = state.send_ek_chunk();

                Ok(SendResult {
                    msg,
                    key,
                    state: State::HeaderSent(state),
                })
            }
            
            State::Ct1Received(mut state) => {
                let (msg, _epoch, key) = state.send_ek_chunk();

                Ok(SendResult {
                    msg,
                    key,
                    state: State::Ct1Received(state),
                })
            }
            
            State::EkSentCt1Received(state) => {
                let (msg, _epoch, key) = state.send_null_message();

                Ok(SendResult {
                    msg,
                    key,
                    state: State::EkSentCt1Received(state),
                })
            }
            
            State::NoHeaderReceived(state) => {
                let (msg, _epoch, key) = state.send_null_message();

                Ok(SendResult {
                    msg,
                    key,
                    state: State::NoHeaderReceived(state),
                })
            }
            
            State::HeaderReceived(state) => {
                let (new_state,msg,_epoch, key) = state.send_ct1_chunk();

                Ok(SendResult {
                    msg,
                    key,
                    state: new_state,
                })
            }
            
            State::Ct1Sampled(mut state) => {
                let (msg, _epoch, key) = state.send_ct1_chunk();

                Ok(SendResult {
                    msg,
                    key,
                    state: State::Ct1Sampled(state),
                })
            }
            
            State::EkReceivedCt1Sampled(mut state) => {
                let (msg, _epoch, key) = state.send_ct1_chunk();

                Ok(SendResult {
                    msg,
                    key,
                    state: State::EkReceivedCt1Sampled(state),
                })
            }
            
            State::Ct2Sampled(mut state) => {
                let (msg, _epoch, key) = state.send_ct2_chunk();

                Ok(SendResult {
                    msg,
                    key,
                    state: State::Ct2Sampled(state),
                })
            }
            
            State::Ct1Acknowledged(state) => {
                let (msg, _epoch, key) = state.send_null_message();

                Ok(SendResult {
                    msg,
                    key,
                    state: State::Ct1Acknowledged(state),
                })
            }
        }
    }
}