use std::thread::JoinHandle;

use crossbeam_channel::Receiver;

pub struct ProxyThreadPool<T : Send + 'static, F : WorkGen<T>> {
    pub workers : u16,
    pub handles : Vec<JoinHandle<()>>,
    pub channel : Receiver<T>,
    pub spawner : F
}

pub trait Runner<T : Send + 'static> {
    fn run(&mut self, v : T);
}

pub trait WorkGen<T : Send + 'static> {
    fn gen(&self) -> impl Runner<T> + Send + 'static;
}

impl<T : Send + 'static,  F : WorkGen<T>> ProxyThreadPool<T, F> {
    pub fn new(workers : u16, channel : Receiver<T>, f : F) -> Self {
        Self {
            workers,
            handles : Vec::with_capacity(workers as usize),
            channel,
            spawner : f
        }
    }

    pub fn init(&mut self) -> Result<(), std::io::Error> {
        for i in 0..self.workers {
            let handle = self.spawn_worker(i)?;
            self.handles.push(handle);
        }
        Ok(())
    }
    fn spawn_worker(&self, id : u16) -> Result<JoinHandle<()>, std::io::Error> {
        let receiver = self.channel.clone();
        let mut worker = self.spawner.gen();
        std::thread::Builder::new().name(format!("PxyWorker{}",id)).spawn(move || {
            loop {
                let work = match receiver.recv() {
                    Ok(v) => v,
                    Err(_) => break
                };
                worker.run(work);
            }
        })
    }
    pub fn revive(&mut self) {
        let mut pos = 0;
        let mut finished_threads = Vec::new();
        for worker in self.handles.iter_mut() {
            if worker.is_finished() {
                finished_threads.push(pos);
            }
            pos += 1;
        }
        for id in finished_threads {
            let handle = match self.spawn_worker(pos) {
                Ok(v) => v,
                Err(_) => return
            };
            let worker = match self.handles.get_mut(id as usize) {
                Some(v) => v,
                None => continue
            };
            *worker = handle;
        }
    }
}
