use crate::{ EncodedChunk, Epoch};


pub enum MessageData{
    None,
    Hdr(EncodedChunk),
    Ek(EncodedChunk),
    EkCt1Ack(EncodedChunk),
    Ct1Ack(bool),
    Ct1(EncodedChunk),
    Ct2(EncodedChunk),
}

pub struct Message{
    pub epoch: Epoch,
    pub data: MessageData,
}