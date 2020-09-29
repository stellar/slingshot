use std;

// In this application we wrap all I/O errors
pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
