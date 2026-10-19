use crate::ml_kem_braid::authenticator::Authenticator;
use crate::ml_kem_braid::config::{Ct1Config, Ct2Config, EkVectorConfig, HeaderConfig};
use crate::ml_kem_braid::decoder::Decoder;
use crate::ml_kem_braid::encoder::Encoder;
use crate::ml_kem_braid::kdf::kdf_ok;
use crate::ml_kem_braid::kem::EncapsulationState;
use crate::ml_kem_braid::messages::MessageData::{Ct1, Ek, Hdr};
use crate::ml_kem_braid::messages::{Message, MessageData};
use crate::ml_kem_braid::util::concatenation;
use crate::ml_kem_braid::{kem, util};
use crate::{Epoch, EpochSecret};

pub enum State {
    KeyUnsampled(KeyUnsampled),
    KeySampled(KeySampled),
    HeaderSent(HeaderSent),
    Ct1Received(Ct1Received),
    EkSentCt1Received(EkSentCt1Received),
    NoHeaderReceived(NoHeaderReceived),
    HeaderReceived(HeaderReceived),
    Ct1Sampled(Ct1Sampled),
    EkReceivedCt1Sampled(EkReceivedCt1Sampled),
    Ct2Sampled(Ct2Sampled),
    Ct1Acknowledged(Ct1Acknowledged)
}
pub struct KeyUnsampled{
    pub epoch: Epoch,
    pub(super) auth: Authenticator
}

pub struct KeySampled{
    pub(crate) epoch: Epoch,
    auth: Authenticator,
    header_encoder: Encoder,
    dk: kem::DecapsulationKey,
    ek_vector: kem::EncapsulationKey,
    ek_seed:kem::Hdr,
    hek: Vec<u8>
}

pub struct HeaderSent{
    pub epoch: Epoch,
    auth: Authenticator,
    dk: kem::DecapsulationKey,
    ct1_decoder: Decoder,
    ek_encoder: Encoder
}

pub struct Ct1Received{
    pub(crate) epoch: Epoch,
    auth: Authenticator,
    dk: kem::DecapsulationKey,
    ct1: Vec<u8>,
    ek_encoder: Encoder
}

pub struct EkSentCt1Received{
    pub(crate) epoch: Epoch,
    auth: Authenticator,
    dk: kem::DecapsulationKey,
    ct1: Vec<u8>,
    ct2_decoder: Decoder
}

pub struct NoHeaderReceived{
    pub(crate) epoch: Epoch,
    auth: Authenticator,
    header_decoder: Decoder
}

pub struct HeaderReceived{
    pub epoch: Epoch,
    auth: Authenticator,
    ek_seed: kem::Hdr,
    hek: Vec<u8>,
    ek_decoder: Decoder
}

pub struct Ct1Sampled{
    pub(crate) epoch: Epoch,
    auth: Authenticator,
    ek_seed: kem::Hdr,
    hek: Vec<u8>,
    encapsulation_secret: kem::EncapsulationKey,
    ct1: EncapsulationState,
    ct1_encoder: Encoder,
    ek_decoder: Decoder
}

pub struct EkReceivedCt1Sampled{
    pub(crate) epoch: Epoch,
    auth: Authenticator,
    encapsulation_secret: kem::EncapsulationKey,
    ct1: EncapsulationState,
    ek_seed: kem::Hdr,
    ek_vector: kem::EncapsulationKey,
    ct1_encoder: Encoder
}

pub struct Ct2Sampled{
    pub epoch: Epoch,
    auth: Authenticator,
    ct2_encoder: Encoder
}

pub struct Ct1Acknowledged{
    pub(crate) epoch: Epoch,
    auth: Authenticator,
    encapsulation_secret: kem::EncapsulationKey,
    ek_seed: kem::Hdr,
    hek: Vec<u8>,
    ct1: EncapsulationState,
    ek_decoder: Decoder
}

impl KeyUnsampled{
    pub fn new(auth_key: &[u8]) -> Self {
        Self {
            epoch: 1,
            auth: Authenticator::new(auth_key, 1),
        }
    }

    pub fn send(self) -> (State,Message, Epoch, Option<EpochSecret>) {
        let key = kem::keygen();

        let hek = util::sha3_256(
            &concatenation(
                &[&key.ek_seed,
                    &key.ek_vector
                ]
            )
        );

        let header = concatenation(
            &[
                &key.ek_seed,
                &hek
            ]
        );


        let mac = self.auth.mac_hdr(self.epoch, &header);

        let mut header_encoder = Encoder::new(
            concatenation(
                &[
                    &header,
                    &mac
                ]
            ).to_vec(),
            Box::new(HeaderConfig::default()),
            self.epoch
        ).unwrap();

        let chunk = header_encoder.next_chunk();

        let message = Message{
            epoch: self.epoch,
            data: Hdr(chunk.unwrap()),
        };

        let sending_epoch = self.epoch - 1;

        let key_sampled = State::KeySampled(
            KeySampled {
                epoch: self.epoch,
                auth: self.auth,
                header_encoder,
                dk: key.dk,
                ek_vector: key.ek_vector,
                ek_seed: key.ek_seed,
                hek: hek.to_vec(),
            }
        );

        (
            key_sampled,
            message,
            sending_epoch,
            None
        )
    }

    pub fn receive(self) -> (Epoch,Option<EpochSecret>){
        let sending_epoch = self.epoch - 1;
        (
            sending_epoch,
            None
        )
    }
}

impl KeySampled{
    pub fn send_header(&mut self) -> (Message, Epoch, Option<EpochSecret>){
        let chunk = self.header_encoder.next_chunk();

        let message = Message{
            epoch: self.epoch,
            data: Hdr(chunk.unwrap()),
        };

        let sending_epoch = self.epoch - 1;

        (
            message,
            sending_epoch,
            None
        )
    }

    pub fn receive_ct1(self, message: Message) -> (State,Epoch, Option<EpochSecret>){
        let sending_epoch = self.epoch - 1;

        if message.epoch == self.epoch {
            if let Ct1(chunk) = message.data {
                let mut ct1_decoder = Decoder::new(
                    &Ct1Config::default()
                );
                ct1_decoder.add_chunk(chunk);
                let ek_encoder = Encoder::new(
                    self.ek_vector,
                    Box::new(EkVectorConfig::default()),
                    self.epoch
                ).unwrap();

                let header_sent = HeaderSent{
                    epoch: self.epoch,
                    auth: self.auth,
                    dk: self.dk,
                    ct1_decoder,
                    ek_encoder
                };

                (State::HeaderSent(header_sent), sending_epoch, None)
            } else {
                panic!("Expected Ct1 message data");
            }
        }
        else{
            (State::KeySampled(self), sending_epoch, None)
        }
    }
}

impl HeaderSent{
    pub fn send_ek_chunk(&mut self)->(Message,Epoch,Option<EpochSecret>){
        let chunk = self.ek_encoder.next_chunk();

        let message = Message{
            epoch:self.epoch,
            data: Ek(chunk.unwrap())
        };

        let sending_epoch = self.epoch - 1;
        (
            message,
            sending_epoch,
            None
        )
    }

    pub fn receive_ct1_chunk(mut self,message:Message)->(State,Epoch,Option<EpochSecret>){
        let receiving_epoch = self.epoch - 1;

        if message.epoch == self.epoch {
            if let Ct1(chunk) = message.data {

                self.ct1_decoder.add_chunk(chunk);



                if self.ct1_decoder.has_message(){
                    let ct1 = self.ct1_decoder.message(&Ct1Config::default()).unwrap();

                    let ct1_received = Ct1Received{
                        epoch: self.epoch,
                        auth: self.auth,
                        dk: self.dk,
                        ct1,
                        ek_encoder: self.ek_encoder
                    };
                    (State::Ct1Received(ct1_received), receiving_epoch, None)
                }
                else{
                    (State::HeaderSent(self), receiving_epoch, None)
                }

            }
            else {
                panic!("Expected Ct1 message data");
            }
        }
        else{
            panic!("Expected Ct1 message data");
        }
    }
}

impl Ct1Received{
    pub fn send_ek_chunk(&mut self)->(Message,Epoch,Option<EpochSecret>){
        let chunk = self.ek_encoder.next_chunk();

        let message = Message{
            epoch:self.epoch,
            data: Ek(chunk.unwrap())
        };

        let sending_epoch = self.epoch - 1;

        (
            message,
            sending_epoch,
            None
        )
    }

    pub fn receive_ct2_chunk(self,message:Message)->(State,Epoch,Option<EpochSecret>){
        let receiving_epoch = self.epoch - 1;

        if message.epoch == self.epoch {
            if let MessageData::Ct2(chunk) = message.data {
                let mut ct2_decoder = Decoder::new(
                    &Ct2Config::default()
                );

                ct2_decoder.add_chunk(chunk);

                let ek_sent_ct1_received = EkSentCt1Received {
                    epoch: self.epoch,
                    auth: self.auth,
                    dk: self.dk,
                    ct1: self.ct1,
                    ct2_decoder
                };

                (State::EkSentCt1Received(ek_sent_ct1_received), receiving_epoch, None)
            } else {
                panic!("Expected Ct2 message data");
            }
        } else {
            panic!("Expected Ct2 message data");
        }
    }
}

impl EkSentCt1Received {
    pub fn send_null_message(&self) -> (Message, Epoch, Option<EpochSecret>) {
        let message = Message {
            epoch: self.epoch,
            data: MessageData::None
        };

        let sending_epoch = self.epoch - 1;

        (
            message,
            sending_epoch,
            None
        )
    }

    pub fn receive_ct2_chunk(
        mut self,
        message: Message,
    ) -> (State, Epoch, Option<EpochSecret>) {
        let receiving_epoch = self.epoch - 1;

        if message.epoch != self.epoch {
            panic!("Expected Ct2 message data");
        }

        if let MessageData::Ct2(chunk) = message.data {
            self.ct2_decoder.add_chunk(chunk);

            // CT2 is still incomplete.
            if !self.ct2_decoder.has_message() {
                return (
                    State::EkSentCt1Received(self),
                    receiving_epoch,
                    None,
                );
            }

            let ct2_with_mac = self
                .ct2_decoder
                .message(&Ct2Config::default())
                .unwrap();

            let ct2 = &ct2_with_mac[..kem::CT2_SIZE];
            let mac = &ct2_with_mac[kem::CT2_SIZE..];

            let mut ss = kem::decaps(
                &self.dk,
                &self.ct1,
                &ct2.to_vec(),
            );

            ss = kdf_ok(
                ss,
                self.epoch,
            );

            self.auth.update(
                self.epoch,
                &ss,
            );

            self.auth.verify_ct(
                self.epoch,
                &*concatenation(&[
                    &self.ct1,
                    &ct2,
                ]),
                mac,
            );

            let header_decoder = Decoder::new(
                &HeaderConfig::default(),
            );

            let no_header_received = NoHeaderReceived {
                epoch: self.epoch + 1,
                auth: self.auth,
                header_decoder,
            };

            let epoch_key = EpochSecret {
                epoch: self.epoch,
                secret: ss,
            };

            (
                State::NoHeaderReceived(no_header_received),
                receiving_epoch,
                Some(epoch_key),
            )
        } else {
            panic!("Expected Ct2 message data");
        }
    }
}

impl NoHeaderReceived{
    pub fn send_null_message(&self)->(Message,Epoch,Option<EpochSecret>){

        let sending_epoch = self.epoch - 1;

        let no_header_null_message = Message{
            epoch:self.epoch,
            data: MessageData::None
        };

        (
            no_header_null_message,
            sending_epoch,
            None
        )
    }

    pub fn receive_hdr_chunk(mut self,message: Message) -> (State,Epoch,Option<EpochSecret>){
        let receiving_epoch = self.epoch - 1;

        if message.epoch == self.epoch {
            if let MessageData::Hdr(hdr) = message.data {
                self.header_decoder.add_chunk(hdr);

                if self.header_decoder.has_message() {
                    let header_with_mac = self.header_decoder.message(&HeaderConfig::default()).unwrap();

                    let header = &header_with_mac[..96];
                    let mac = &header_with_mac[96..];

                    let ek_seed = &header[..64];
                    let hek = &header[64..];

                    self.auth.verify_hdr(
                        self.epoch,
                        &header,
                        &mac
                    );

                    let ek_decoder = Decoder::new(
                        &EkVectorConfig::default()
                    );

                    let header_received = HeaderReceived{
                        epoch:self.epoch,
                        auth:self.auth,
                        ek_seed: ek_seed.to_vec(),
                        hek: hek.to_vec(),
                        ek_decoder
                    };

                    (State::HeaderReceived(header_received), receiving_epoch, None)
                } else {
                    (State::NoHeaderReceived(self), receiving_epoch, None)                }
            }else {
                panic!("Expected HdR message data");
            }
        }else {
            panic!("Expected HdR message data");
        }
    }
}

impl HeaderReceived {
    pub fn send_ct1_chunk(self) -> (State,Message,Epoch,Option<EpochSecret>){
        let (encaps_secret, ct1, mut ss) = kem::encaps1(
            &concatenation(
                &[
                    &self.ek_seed,
                    &self.hek
                ]
            ).to_vec()
        );

        ss = kdf_ok(
            ss,
            self.epoch
        );

        let mut ct1_encoder = Encoder::new(
            ct1.to_vec(),
            Box::new(EkVectorConfig::default()),
            self.epoch
        ).unwrap();

        let chunk = ct1_encoder.next_chunk();

        let message = Message{
            epoch:self.epoch,
            data: Ct1(chunk.unwrap())
        };

        let ct1_sampled = Ct1Sampled{
            epoch: self.epoch,
            auth: self.auth,
            ek_seed: self.ek_seed,
            hek: self.hek,
            encapsulation_secret: encaps_secret,
            ct1,
            ct1_encoder,
            ek_decoder: self.ek_decoder
        };

        let epoch_key = EpochSecret{
            epoch: self.epoch,
            secret: ss
        };

        let sending_epoch = self.epoch - 1;

        (
            State::Ct1Sampled(ct1_sampled),
            message,
            sending_epoch,
            Some(epoch_key)
        )

    }

    pub fn receive(&self) -> (Epoch,Option<EpochSecret>){
        let receiving_epoch = self.epoch - 1;

        (
            receiving_epoch,
            None
            )
    }
}

impl Ct1Sampled {
    pub fn send_ct1_chunk(&mut self) -> (Message,Epoch,Option<EpochSecret>) {
        let chunk = self.ct1_encoder.next_chunk();

        let message = Message {
            epoch: self.epoch,
            data: Ct1(chunk.unwrap())
        };
        let receiving_epoch = self.epoch - 1;
        (
            message,
            receiving_epoch,
            None
        )
    }

    pub fn receive_ek_chunk(mut self,message:Message) -> (State,Epoch,Option<EpochSecret>) {
        let receiving_epoch = self.epoch - 1;

        if message.epoch == self.epoch {
            if let MessageData::Ek(chunk) = message.data {
                self.ek_decoder.add_chunk(chunk);

                if self.ek_decoder.has_message() {
                    let ek_vector = self.ek_decoder.message(&EkVectorConfig::default()).unwrap();

                    if util::sha3_256(
                        &concatenation(
                            &[
                                &self.ek_seed,
                                &ek_vector
                            ]
                        )
                    ) != self.hek.as_slice() {
                        panic!("HEK verification failed");
                    }

                    let next_state = State::EkReceivedCt1Sampled(
                        EkReceivedCt1Sampled {
                            epoch: self.epoch,
                            auth: self.auth,
                            encapsulation_secret: self.encapsulation_secret,
                            ct1: self.ct1,
                            ek_seed: self.ek_seed,
                            ek_vector,
                            ct1_encoder: self.ct1_encoder,
                        }
                    );

                    (next_state, receiving_epoch, None)
                } else {
                    (State::Ct1Sampled(self), receiving_epoch, None)
                }
            } else if let MessageData::EkCt1Ack(chunk) = message.data {
                self.ek_decoder.add_chunk(chunk);

                if self.ek_decoder.has_message() {
                    let ek_vector = self.ek_decoder.message(&EkVectorConfig::default()).unwrap();

                    if util::sha3_256(&concatenation(&[&self.ek_seed, &ek_vector])) != self.hek.as_slice() {
                        panic!("HEK verification failed");
                    }

                    let ct2 = kem::encaps2(
                        &self.encapsulation_secret,
                        &self.ct1
                    );

                    let mac = self.auth.mac_ct(
                        self.epoch,
                        &*concatenation(
                            &[&self.ct1, &ct2]
                        )
                    );

                    let ct2_encoder = Encoder::new(
                        concatenation(
                            &[
                                &ct2,
                                &mac
                            ]
                        ).to_vec(),
                        Box::new(Ct2Config::default()),
                        self.epoch
                    ).unwrap();



                    let ct2_sampled = State::Ct2Sampled(
                        Ct2Sampled{
                            epoch: self.epoch,
                            auth: self.auth,
                            ct2_encoder
                        }
                    );

                    (ct2_sampled, receiving_epoch, None)
                } else {
                    let state = State::Ct1Acknowledged(
                        Ct1Acknowledged{
                            epoch: self.epoch,
                            auth: self.auth,
                            encapsulation_secret: self.encapsulation_secret,
                            ek_seed: self.ek_seed,
                            hek: self.hek,
                            ct1: self.ct1,
                            ek_decoder: self.ek_decoder
                        }
                    );
                    (state, receiving_epoch, None)
                }
            } else {
                panic!("Expected Ek message data");
            }
        } else {
            panic!("Expected Ek message data");
        }
    }
}

impl EkReceivedCt1Sampled {
    pub fn send_ct1_chunk(&mut self) -> (Message,Epoch,Option<EpochSecret>) {
        let chunk = self.ct1_encoder.next_chunk();
        let sending_epoch = self.epoch - 1;

        let message = Message{
            epoch: self.epoch,
            data: Ct1(chunk.unwrap())
        };

        (
            message,
            sending_epoch,
            None
        )
    }

    pub fn receive_ek_ct1_ack_chunk(self,message:Message) -> (State,Epoch,Option<EpochSecret>) {
        let receiving_epoch = self.epoch - 1;

        if message.epoch == self.epoch {
            if let MessageData::EkCt1Ack(_chunk) = message.data {
                let ct2 = kem::encaps2(
                    &self.encapsulation_secret,
                    &self.ct1
                );

                let mac = self.auth.mac_ct(
                    self.epoch,
                    &*concatenation(
                        &[&self.ct1, &ct2]
                    )
                );

                let ct2_encoder = Encoder::new(
                    concatenation(
                        &[
                            &ct2,
                            &mac
                        ]
                    ).to_vec(),
                    Box::new(Ct2Config::default()),
                    self.epoch
                ).unwrap();

                let ct2_sampled = State::Ct2Sampled(
                    Ct2Sampled {
                        epoch: self.epoch,
                        auth: self.auth,
                        ct2_encoder
                    }
                );

                (ct2_sampled, receiving_epoch, None)
            } else {
                panic!("Expected EkCt1Ack message data");
            }
        } else {
            panic!("Expected EkCt1Ack message data");
        }
    }
}


impl Ct1Acknowledged {
    pub fn send_null_message(&self) -> (Message,Epoch,Option<EpochSecret>) {

        let no_ct1_ack_null_message = Message{
            epoch:self.epoch,
            data: MessageData::None
        };

        (
            no_ct1_ack_null_message,
            self.epoch-1,
            None
        )
    }

    pub fn receive_ek_ct1_ack_message(mut self,message: Message) -> (State,Epoch,Option<EpochSecret>) {
        let receiving_epoch = self.epoch - 1;

        if message.epoch == self.epoch {
            if let MessageData::EkCt1Ack(chunk) = message.data {
                self.ek_decoder.add_chunk(chunk);
                if self.ek_decoder.has_message() {
                    let ek_vector = self.ek_decoder.message(&EkVectorConfig::default()).unwrap();

                    if util::sha3_256(
                        &concatenation(
                            &[
                                &self.ek_seed,
                                &ek_vector
                            ]
                        )
                    ) != self.hek.as_slice() {
                        panic!("HEK verification failed");
                    }

                    let ct2 = kem::encaps2(
                        &self.encapsulation_secret,
                        &self.ct1
                    );

                    let mac = self.auth.mac_ct(
                        self.epoch,
                        &*concatenation(
                            &[&self.ct1, &ct2]
                        )
                    );

                    let ct2_encoder = Encoder::new(
                        concatenation(
                            &[
                                &ct2,
                                &mac
                            ]
                        ).to_vec(),
                        Box::new(Ct2Config::default()),
                        self.epoch
                    ).unwrap();

                    let ct2_sampled = State::Ct2Sampled(
                        Ct2Sampled{
                            epoch: self.epoch,
                            auth: self.auth,
                            ct2_encoder
                        }
                    );
                    (ct2_sampled, receiving_epoch, None)
                } else {
                    (State::Ct1Acknowledged(self), receiving_epoch, None)
                }
            } else {
                panic!("Expected EkCt1Ack message data");
            }
        } else {
            panic!("Expected EkCt1Ack message data");
        }
    }
}

impl Ct2Sampled {
    pub fn send_ct2_chunk(&mut self) -> (Message,Epoch,Option<EpochSecret>) {
        let chunk = self.ct2_encoder.next_chunk();
        let sending_epoch = self.epoch - 1;

        let message = Message{
            epoch: self.epoch,
            data: MessageData::Ct2(chunk.unwrap())
        };

        (
            message,
            sending_epoch,
            None
        )
    }

    pub fn receive(self,message: Message) -> (State,Epoch,Option<EpochSecret>) {
        let receiving_epoch = self.epoch - 1;

        if message.epoch == self.epoch + 1 {
            let state = KeyUnsampled{
                    epoch: self.epoch + 1,
                    auth: self.auth
            };
            (State::KeyUnsampled(state), receiving_epoch, None)
        } else {
            (State::Ct2Sampled(self), receiving_epoch, None)
        }
    }

}

impl State{
    pub fn init_a(shares_secret:Vec<u8>) -> State {
        let epoch :Epoch = 1;

        let auth = Authenticator::new(&shares_secret, epoch);

        State::KeyUnsampled(
            KeyUnsampled{
                epoch,
                auth
            }
        )
    }

    pub fn init_b(shares_secret:Vec<u8>) -> State {

        let epoch :Epoch = 1;

        let auth = Authenticator::new(&shares_secret, epoch);

        State::NoHeaderReceived(
            NoHeaderReceived{
                epoch,
                auth,
                header_decoder: Decoder::new(
                    &HeaderConfig::default()
                )
            }
        )
    }
}






