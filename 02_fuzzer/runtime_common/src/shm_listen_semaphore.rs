use angora_common::listen_semaphore;
use lazy_static::lazy_static;
use std::sync::Mutex;
lazy_static! {
    pub static ref LISTEN_SEM: Mutex<Option<listen_semaphore::ShmListenSemaphore>> = Mutex::new(listen_semaphore::ShmListenSemaphore::get_from_env_id());
}

#[ctor]
fn init() {
    lazy_static::initialize(&LISTEN_SEM);
}