# MSx7x Flasher
Tool to read and flash the MSV70 and MSS70 DMEs. Can read/write full and partial binaries from both. It will automatically correct checksums and bypass signature checks.


### Prerequisites
This application uses .Net Framework 4.5.2

Any INPA-compatible OBDII cable should work with this application. 

You will need EdiabasLib.dll to compile and run this application.
The application assumes you have an ediabas installation in the default directory.
If you don't have / want Ediabas installed, you will need to find a copy of MSV70.prg or MSS70.prg, and set the .config file to reflect the directory and filename of those files.
Most of my testing has been with MSV70.prg, so I recommend using that.


### Usage
Change the settings as necessary in the 'MSx7x Flasher.exe.config' file. 
Default port is FTDI0, default sgbd directory is C:\Ediabas\ECU, and default sgbd is MSV70.prg



###WIP


## License

This project is licensed under The GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details

## Disclaimer: 
This program is inherently invasive, and can render your DME unbootable and your car undriveable. Care must be taken when using this application. In no respect shall the authors or contributors incur any liability for any damages, including, but limited to, direct, indirect, special, or consequential damages arising out of, resulting from, or any way connected to the use of the application, whether or not based upon warranty, contract, tort, or otherwise; whether or not injury was sustained by persons or property or otherwise; and whether or not loss was sustained from, or arose out of, the results of, the item, or any services that may be provided by the authors and contributors.
