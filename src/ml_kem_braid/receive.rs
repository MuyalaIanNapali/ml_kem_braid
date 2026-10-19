use crate::{EpochSecret, Error};
use crate::ml_kem_braid::messages::{Message, MessageData};
use crate::ml_kem_braid::states::State;
use std::cmp::Ordering;

pub struct Receive {
    pub key: Option<EpochSecret>,
    pub state: State,
}

impl State {
    pub fn receive(self, message: Message) -> Result<Receive, Error> {
        let mut key = None;

        let state = match self {
            State::KeyUnsampled(state) => match message.epoch.cmp(&state.epoch) {
                Ordering::Greater => {
                    return Err(Error::EpochOutOfRange(message.epoch));
                }
                Ordering::Less => Self::KeyUnsampled(state),
                Ordering::Equal => Self::KeyUnsampled(state),
            }
            State::KeySampled(state) => {
                match message.epoch.cmp(&state.epoch) {
                    Ordering::Greater => {
                        return Err(Error::EpochOutOfRange(message.epoch));
                    }

                    Ordering::Less => {
                        Self::KeySampled(state)
                    }

                    Ordering::Equal => {
                        match message.data {
                            MessageData::Ct1(_) => {
                                let (new_state, _epoch, key_option) =
                                    state.receive_ct1(message);

                                key = key_option;

                                new_state
                            }

                            _ => {
                                Self::KeySampled(state)
                            }
                        }
                    }
                }
            }
            State::HeaderSent(state) => match message.epoch.cmp(&state.epoch) {
                Ordering::Greater => {
                    return Err(Error::EpochOutOfRange(message.epoch));
                }
                Ordering::Less => Self::HeaderSent(state),
                Ordering::Equal => {
                    match message.data {
                        MessageData::Ct1(_) => {
                            let (new_state, _epoch, key_option) =
                                state.receive_ct1_chunk(message);

                            key = key_option;

                            new_state
                        }

                        _ => {
                            Self::HeaderSent(state)
                        }
                    }
                }
            }
            State::Ct1Received(state) => match message.epoch.cmp(&state.epoch) {
                Ordering::Greater => {
                    return Err(Error::EpochOutOfRange(message.epoch));
                }
                Ordering::Less => Self::Ct1Received(state),
                Ordering::Equal => {
                    match message.data {
                        MessageData::Ct2(_) => {
                            let (new_state, _epoch, key_option) =
                                state.receive_ct2_chunk(message);

                            key = key_option;

                            new_state
                        }

                        _ => {
                            Self::Ct1Received(state)
                        }
                    }
                }
            }
            State::EkSentCt1Received(state) => match message.epoch.cmp(&state.epoch) {
                Ordering::Greater => {
                    return Err(Error::EpochOutOfRange(message.epoch));
                }
                Ordering::Less => Self::EkSentCt1Received(state),
                Ordering::Equal => {
                    match message.data {
                        MessageData::Ct2(_) => {
                            let (new_state, _epoch, key_option) =
                                state.receive_ct2_chunk(message);

                            key = key_option;

                            new_state
                        }

                        _ => {
                            Self::EkSentCt1Received(state)
                        }
                    }
                }
            }
            State::NoHeaderReceived(state) => {
                match message.epoch.cmp(&state.epoch) {
                    Ordering::Greater => {
                        return Err(Error::EpochOutOfRange(message.epoch));
                    }
                    Ordering::Less => Self::NoHeaderReceived(state),
                    Ordering::Equal => {
                        match message.data {
                            MessageData::Hdr(_) => {
                                let (new_state, _epoch, key_option) =
                                    state.receive_hdr_chunk(message);

                                key = key_option;

                                new_state
                            }

                            _ => {
                                Self::NoHeaderReceived(state)
                            }
                        }
                    }
                }
            }

            State::HeaderReceived(state) => {
                match message.epoch.cmp(&state.epoch) {
                    Ordering::Greater => {
                        return Err(Error::EpochOutOfRange(message.epoch));
                    }
                    Ordering::Less => Self::HeaderReceived(state),
                    Ordering::Equal => Self::HeaderReceived(state),
                }
            }

            State::Ct1Sampled(state) => {
                match message.epoch.cmp(&state.epoch) {
                    Ordering::Greater => {
                        return Err(Error::EpochOutOfRange(message.epoch));
                    }
                    Ordering::Less => Self::Ct1Sampled(state),
                    Ordering::Equal => {
                        match message.data {
                            MessageData::Ct1(_) => {
                                let (state, _epoch, key_option) =
                                    state.receive_ek_chunk(message);

                                key = key_option;

                                state
                            }

                            _ => {
                                Self::Ct1Sampled(state)
                            }
                        }
                    }
                }
            }

            State::EkReceivedCt1Sampled(state) => {
                match message.epoch.cmp(&state.epoch) {
                    Ordering::Greater => {
                        return Err(Error::EpochOutOfRange(message.epoch));
                    }
                    Ordering::Less => Self::EkReceivedCt1Sampled(state),
                    Ordering::Equal => {
                        match message.data {
                            MessageData::Ct2(_) => {
                                let (new_state, _epoch, key_option) =
                                    state.receive_ek_ct1_ack_chunk(message);

                                key = key_option;

                                new_state
                            }

                            _ => {
                                Self::EkReceivedCt1Sampled(state)
                            }
                        }
                    }
                }
            }

            State::Ct2Sampled(state) => {
                match message.epoch.cmp(&state.epoch) {
                    Ordering::Greater => {
                        return Err(Error::EpochOutOfRange(message.epoch));
                    }
                    Ordering::Less => Self::Ct2Sampled(state),
                    Ordering::Equal => {
                        match message.data {
                            MessageData::Ct2(_) => {
                                let (new_state, _epoch, key_option) =
                                    state.receive(message);

                                key = key_option;

                                new_state
                            }

                            _ => {
                                Self::Ct2Sampled(state)
                            }
                        }
                    }
                }
            }

            State::Ct1Acknowledged(state) => {
                match message.epoch.cmp(&state.epoch) {
                    Ordering::Greater => {
                        return Err(Error::EpochOutOfRange(message.epoch));
                    }
                    Ordering::Less => Self::Ct1Acknowledged(state),
                    Ordering::Equal => {
                        match message.data {
                            MessageData::Ct2(_) => {
                                let (new_state, _epoch, key_option) =
                                    state.receive_ek_ct1_ack_message(message);

                                key = key_option;

                                new_state
                            }

                            _ => {
                                Self::Ct1Acknowledged(state)
                            }
                        }
                    }
                }
            }

        };
        Ok(Receive { key, state })
    }
}
