use tokio::sync::broadcast;
use tokio::sync::mpsc;

/// Sender of the commands.
pub type CommandSender = mpsc::Sender<Command>;

/// Receiver of the commands.
pub type CommandReceiver = mpsc::Receiver<Command>;

/// Creates a command delivery channel for sending commands from UI components to the blockchain state machine.
pub fn command_channel(capacity: usize) -> (CommandSender, CommandReceiver) {
    mpsc::channel(capacity)
}

/// Sender of the blockchain events.
pub type EventSender = broadcast::Sender<Event>;

/// Receiver of the blockchain events.
pub type EventReceiver = broadcast::Receiver<Event>;

/// Creates an event broadcast channel for sending blockchain events to the UI components.
pub fn event_channel(capacity: usize) -> (EventSender, EventReceiver) {
    broadcast::channel(capacity)
}

/// A command sent by the UI/API into the blockchain state machine.
#[derive(Clone, Debug)]
pub enum Command {}

/// Type for all events about the BC state into the UI.
#[derive(Clone, Debug)]
pub enum Event {}
