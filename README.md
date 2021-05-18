# Smart Alec
Smart Alec - Tells you what got loaded

Brief Overview:
Smart Alec is a tool which can help one analyze userland rootkits in Android.
The tool can be re-purposed to study several different malicious behaviours.

It helps one capture the state of device before and after the infection. By state we imply all the processes running on the system, along with all the modules loaded within those processes, their size, path, permissions etc.
The tool then helps run comparative analysis on the states and helps the investigator to narrow down on any malicious .so files that might have been loaded as a part of the infection.
Once the .so is identified, the tool enables dumping the ELF from the memory, so that it can be further reversed and analyzed using any of the popular RE tools such as Binary Ninja, Cutter etc.

A detailed documentation along with the setup guide is coming soon! Please watch out this space for updates.
