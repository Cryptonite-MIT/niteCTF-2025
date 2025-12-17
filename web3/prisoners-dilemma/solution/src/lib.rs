pub mod processor;
use processor::process_instruction;

solana_program::entrypoint!(process_instruction);