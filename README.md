# Syskey

Syskey is a simple NtUserGetAsyncKeyState syscall wrapper.
This implementation was done in a way to avoid both imports and direct calling of GetAsyncKeyState for obscurity and security.

## Prodecure:

    Dynamically finds and saves the syscall ID of NtUserGetAsyncKeyState
    Calls the syscall ID using the VK code provided
    Returns as expected
	
## Example usage:
    ```
    if (nt::GetKey(VK_F1) & 0x8000)
      printf("F1 just got called!\n");
    ```
