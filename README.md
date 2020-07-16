# Static-Analysis-Module
To implement the static analysis subsystem, we used the C ++ programming language for the Windows 7 x86 architecture. The static analysis subsystem is implemented as an executable .exe file that is launched with the following arguments:
• -s path_dir_or_file, check files for signature matches;
• -y path_dir_or_file, check files for yara-rules;
• -p path_dir_or_file, file packing definition;
• -v path_dir_or_file, file signature verification.
The static analysis subsystem is a pipe client that sends messages of the following format to the pipe server \\. \ Pipe \ StaticAnalysisModule:
• log.message, message for logging;
• event.message, a message to display on the screen, as a rule, about the maliciousness of the file;
• file (+). PathOfFile, message stating that the file is not malicious;
• file (-). PathOfFile, message that the file is malicious.
Message - message body, PathOfFile - full path of the checked file. (^_^) - is a message separator, placed at the end of each.
The static analysis module does not care whether it is given a directory or file path, since there is a check: a directory or a file. If it is given a directory path, it recursively walks through all the directories and files inside it, checking each file in it in accordance with the previously specified startup argument.
The signature databases were taken from the official ClamAV website: main.hdb, main.hsb, main.fp. The total number of signatures is over 4.5 million records. All three of the above files have the following form of entries: HashString: FileSize: MalwareName. The hash value of the malicious file is stored in MD5. To speed up access to signatures and quickly search for the corresponding signature, it was decided to create our own database of key-value signatures, where signatures taken from the ClamAV database are stored. To implement the key-value database, the LevelDB toolkit was used as C ++ plug-in libraries. Accordingly, if the startup argument is -s, then the static analysis module calculates the hash value of the file in MD5 and searches the database for the signature; if no match is found, then the file has successfully passed the scan, otherwise it is considered malicious.
Some yara rules were taken from github.com to identify a malicious file, and the Yara toolkit was used to determine the malware of the file being scanned. The yara toolkit and yara rules were used in a similar way to determine the packaging of a file. The yara-rules were taken for the following packers: aspack, nkh, rlpack, sogu_packer, upx, vmprotect.
