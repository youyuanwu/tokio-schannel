#![cfg(target_os = "windows")]
// schannel

use std::{
    fmt,
    future::Future,
    io::{self, Read, Write},
    pin::Pin,
    task::{Context, Poll},
};

use schannel::tls_stream::{HandshakeError, MidHandshakeTlsStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// ----------- wrapper for none async/ pollable stream.
pub struct StreamWrapper<S> {
    stream: S,
    context: usize,
}

impl<S> fmt::Debug for StreamWrapper<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.stream, fmt)
    }
}

impl<S> StreamWrapper<S> {
    /// # Safety
    ///
    /// Must be called with `context` set to a valid pointer to a live `Context` object, and the
    /// wrapper must be pinned in memory.
    unsafe fn parts(&mut self) -> (Pin<&mut S>, &mut Context<'_>) {
        debug_assert_ne!(self.context, 0);
        let stream = unsafe { Pin::new_unchecked(&mut self.stream) };
        let context = unsafe { &mut *(self.context as *mut Context<'_>) };
        (stream, context)
    }

    // // internal helper to set context and execute sync function.
    // fn with_context<F, R>(&mut self, ctx: &mut Context<'_>, f: F) -> R
    // where
    //     F: FnOnce(&mut Self) -> R,
    // {
    //     self.context = ctx as *mut _ as usize;
    //     let r = f(self);
    //     self.context = 0;
    //     r
    // }
}

impl<S> Read for StreamWrapper<S>
where
    S: AsyncRead,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (stream, cx) = unsafe { self.parts() };
        let mut buf = ReadBuf::new(buf);
        match stream.poll_read(cx, &mut buf)? {
            Poll::Ready(()) => Ok(buf.filled().len()),
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

impl<S> Write for StreamWrapper<S>
where
    S: AsyncWrite,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (stream, cx) = unsafe { self.parts() };
        match stream.poll_write(cx, buf) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let (stream, cx) = unsafe { self.parts() };
        match stream.poll_flush(cx) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

// cvt error to poll
fn cvt<T>(r: io::Result<T>) -> Poll<io::Result<T>> {
    match r {
        Ok(v) => Poll::Ready(Ok(v)),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
        Err(e) => Poll::Ready(Err(e)),
    }
}

impl<S> StreamWrapper<S> {
    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }
}

/// Wrapper around schannels' tls stream and provide async apis.
#[derive(Debug)]
pub struct TlsStream<S>(schannel::tls_stream::TlsStream<StreamWrapper<S>>);

impl<S> TlsStream<S> {
    // /// Like [`TlsStream::new`](schannel::tls_stream::TlsStream).
    // pub fn new( stream: S) -> Result<Self, ErrorStack> {
    //     ssl::SslStream::new(ssl, StreamWrapper { stream, context: 0 }).map(SslStream)
    // }
    //pub fn poll_connect()

    // pass the ctx in the wrapper and invoke f
    fn with_context<F, R>(self: Pin<&mut Self>, ctx: &mut Context<'_>, f: F) -> R
    where
        F: FnOnce(&mut schannel::tls_stream::TlsStream<StreamWrapper<S>>) -> R,
    {
        let this = unsafe { self.get_unchecked_mut() };
        this.0.get_mut().context = ctx as *mut _ as usize;
        let r = f(&mut this.0);
        this.0.get_mut().context = 0;
        r
    }

    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &schannel::tls_stream::TlsStream<StreamWrapper<S>> {
        &self.0
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut schannel::tls_stream::TlsStream<StreamWrapper<S>> {
        &mut self.0
    }
}

impl<S> AsyncRead for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.with_context(ctx, |s| {
            // TODO: read into uninitialized for optimize
            match cvt(s.read(buf.initialize_unfilled()))? {
                Poll::Ready(nread) => {
                    buf.advance(nread);
                    Poll::Ready(Ok(()))
                }
                Poll::Pending => Poll::Pending,
            }
        })
    }
}

impl<S> AsyncWrite for TlsStream<S>
where
    S: AsyncRead + AsyncWrite,
{
    fn poll_write(self: Pin<&mut Self>, ctx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.with_context(ctx, |s| cvt(s.write(buf)))
    }

    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
        self.with_context(ctx, |s| cvt(s.flush()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
        // TODO: May need to check error and retry
        self.with_context(ctx, |s| cvt(s.shutdown()))
    }
}

// acceptor
pub struct TlsAcceptor {
    inner: schannel::tls_stream::Builder,
}

impl TlsAcceptor {
    pub fn new(inner: schannel::tls_stream::Builder) -> Self {
        Self { inner }
    }

    pub async fn accept<S>(
        &mut self,
        cred: schannel::schannel_cred::SchannelCred,
        stream: S,
    ) -> Result<TlsStream<S>, std::io::Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        handshake(move |s| self.inner.accept(cred, s), stream).await
    }
}

// connector
pub struct TlsConnector {
    inner: schannel::tls_stream::Builder,
}

impl TlsConnector {
    pub fn new(inner: schannel::tls_stream::Builder) -> Self {
        Self { inner }
    }

    pub async fn connect<IO>(
        &mut self,
        cred: schannel::schannel_cred::SchannelCred,
        stream: IO,
    ) -> io::Result<TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        handshake(move |s| self.inner.connect(cred, s), stream).await
    }
}

struct MidHandshake<S>(Option<MidHandshakeTlsStream<StreamWrapper<S>>>);

enum StartedHandshake<S> {
    Done(TlsStream<S>),
    Mid(MidHandshakeTlsStream<StreamWrapper<S>>),
}

struct StartedHandshakeFuture<F, S>(Option<StartedHandshakeFutureInner<F, S>>);
struct StartedHandshakeFutureInner<F, S> {
    f: F,
    stream: S,
}

async fn handshake<F, S>(f: F, stream: S) -> Result<TlsStream<S>, std::io::Error>
where
    F: FnOnce(
            StreamWrapper<S>,
        ) -> Result<
            schannel::tls_stream::TlsStream<StreamWrapper<S>>,
            schannel::tls_stream::HandshakeError<StreamWrapper<S>>,
        > + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let start = StartedHandshakeFuture(Some(StartedHandshakeFutureInner { f, stream }));

    match start.await {
        Err(e) => Err(e),
        Ok(StartedHandshake::Done(s)) => Ok(s),
        Ok(StartedHandshake::Mid(s)) => MidHandshake(Some(s)).await,
    }
}

impl<F, S> Future for StartedHandshakeFuture<F, S>
where
    F: FnOnce(
            StreamWrapper<S>,
        ) -> Result<
            schannel::tls_stream::TlsStream<StreamWrapper<S>>,
            schannel::tls_stream::HandshakeError<StreamWrapper<S>>,
        > + Unpin,
    S: Unpin,
    StreamWrapper<S>: Read + Write,
{
    type Output = Result<StartedHandshake<S>, std::io::Error>;

    fn poll(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
    ) -> Poll<Result<StartedHandshake<S>, std::io::Error>> {
        let inner = self.0.take().expect("future polled after completion");
        let stream = StreamWrapper {
            stream: inner.stream,
            context: ctx as *mut _ as usize,
        };

        match (inner.f)(stream) {
            Ok(mut s) => {
                s.get_mut().context = 0;
                Poll::Ready(Ok(StartedHandshake::Done(TlsStream(s))))
            }
            Err(HandshakeError::Interrupted(mut s)) => {
                s.get_mut().context = 0;
                Poll::Ready(Ok(StartedHandshake::Mid(s)))
            }
            Err(HandshakeError::Failure(e)) => Poll::Ready(Err(e)),
        }
    }
}

// pub struct StartHandShakeFu<S> {
//     f: dyn FnOnce() -> StartHandShake<S>,
// }

// impl<S> Future for StartHandShakeFu<S>
// {
//     type Output = StartHandShake<S>;
// }

impl<S: AsyncRead + AsyncWrite + Unpin> Future for MidHandshake<S> {
    type Output = Result<TlsStream<S>, std::io::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut_self = self.get_mut();
        let mut s = mut_self.0.take().expect("future polled after completion");

        s.get_mut().context = cx as *mut _ as usize;
        match s.handshake() {
            Ok(mut s) => {
                s.get_mut().context = 0;
                Poll::Ready(Ok(TlsStream(s)))
            }
            Err(HandshakeError::Interrupted(mut s)) => {
                s.get_mut().context = 0;
                mut_self.0 = Some(s);
                Poll::Pending
            }
            Err(HandshakeError::Failure(e)) => Poll::Ready(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests;
