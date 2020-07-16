#include <time.h>
#include <tchar.h>
#include <windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <map>
#include <regex>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <iostream>
#include <filesystem>

#include "yaracpp.h"
#include "leveldb/db.h"
#include "openssl/sha.h"
#include "QtCore/QCryptographicHash"
#include "openssl/md5.h"

using namespace std;

#define _CRT_SECURE_NO_WARNINGS

#pragma comment (lib, "wintrust")

// Pipe ID
HANDLE hNamedPipe;
// pipe name
char szPipeName[256] = "\\\\.\\pipe\\StaticAnalysisModule";

ofstream log_file_static_analysis;

yaracpp::YaraDetector yara_for_malware;
yaracpp::YaraDetector yara_for_packer;
leveldb::DB* db_hdb, *db_mdb, *db_hsb, *db_ndb, *db_fp;
leveldb::Options options_hdb, options_mdb, options_hsb, options_ndb, options_fp;

wchar_t* char_to_wchat_t(const char* c);
char* wchar_to_char(const wchar_t* pwchar);
string get_time();
BOOL send_message_to(string message, int choice);
string string_to_hex(const std::string& input);
string sha256(const string str);
string get_sha256_from_file(const string PathFile);
string md5(const string str);
string get_md5_from_file(const string PathFile);
int read_and_check_integrity_db(string FileName, string Integrity);
void parse_and_load_virus_databases(string FolderName, string PathLevelDB);
int scan_by_signature(string file_hash_md5);
int load_yara_rules_for_malware(string PathYaraRules);
int scan_by_yara_rules(string FName);
int load_yara_rules_for_packer(string PathYaraRules);
int identify_packer_by_yara_rules(string FName);
BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile);
void FindFiles(string FName, int choice);
void main(int argc, char* argv[]);

wchar_t* char_to_wchat_t(const char* c)
{
	const size_t cSize = strlen(c) + 1;
	wchar_t* wc = new wchar_t[cSize];
	mbstowcs(wc, c, cSize);

	return wc;
}

char* wchar_to_char(const wchar_t* pwchar)
{
	// get the number of characters in the string.
	int currentCharIndex = 0;
	char currentChar = pwchar[currentCharIndex];

	while (currentChar != '\0')
	{
		currentCharIndex++;
		currentChar = pwchar[currentCharIndex];
	}

	const int charCount = currentCharIndex + 1;

	// allocate a new block of memory size char (1 byte) instead of wide char (2 bytes)
	char* filePathC = (char*)malloc(sizeof(char) * charCount);

	for (int i = 0; i < charCount; i++)
	{
		// convert to char (1 byte)
		char character = pwchar[i];

		*filePathC = character;

		filePathC += sizeof(char);

	}
	filePathC += '\0';

	filePathC -= (sizeof(char) * charCount);

	return filePathC;
}

string string_to_hex(const std::string& input)
{
	static const char* const lut = "0123456789abcdef";
	size_t len = input.length();

	std::string output;
	output.reserve(2 * len);
	for (size_t i = 0; i < len; ++i)
	{
		const unsigned char c = input[i];
		output.push_back(lut[c >> 4]);
		output.push_back(lut[c & 15]);
	}
	return output;
}

string sha256(const string str)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, str.c_str(), str.size());
	SHA256_Final(hash, &sha256);
	stringstream ss;
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		ss << hex << setw(2) << setfill('0') << (int)hash[i];
	}
	return ss.str();
}

string get_sha256_from_file(const string PathFile)
{
	FILE* fd = fopen(PathFile.c_str(), "rb");
	if (!fd) return "";

	fseek(fd, 0, SEEK_END);
	long fSize = ftell(fd);
	fseek(fd, 0, SEEK_SET);

	QCryptographicHash krypo(QCryptographicHash::Sha256);
	const long blockSize = 8192;
	char block[blockSize];
	long c = fSize;
	while (c > 0) {
		fread(block, 1, (c < blockSize) ? c : blockSize, fd);
		krypo.addData(block, (c < blockSize) ? c : blockSize);
		c -= (c < blockSize) ? c : blockSize;
	}
	QByteArray hash = krypo.result();
	std::string QByteArray_to_String(hash.constData(), hash.length());

	string result = string_to_hex(QByteArray_to_String);
	cout << result << endl;
	return result;
}

string md5(const string str)
{
	unsigned char result[MD5_DIGEST_LENGTH];
	MD5((unsigned char*)str.c_str(), str.size(), result);

	std::ostringstream sout;
	sout << std::hex << std::setfill('0');
	for (long long c : result)
	{
		sout << std::setw(2) << (long long)c;
	}
	return sout.str();
}

string get_md5_from_file(const string PathFile)
{
	FILE* fd = fopen(PathFile.c_str(), "rb");
	if (!fd) return "";


	fseek(fd, 0, SEEK_END);
	long fSize = ftell(fd);
	fseek(fd, 0, SEEK_SET);

	QCryptographicHash krypo(QCryptographicHash::Md5);
	const long blockSize = 8192;
	char block[blockSize];
	long c = fSize;
	while (c > 0) {
		fread(block, 1, (c < blockSize) ? c : blockSize, fd);
		krypo.addData(block, (c < blockSize) ? c : blockSize);
		c -= (c < blockSize) ? c : blockSize;
	}
	QByteArray hash = krypo.result();
	std::string QByteArray_to_String(hash.constData(), hash.length());

	string result = string_to_hex(QByteArray_to_String);
	cout << result << endl;
	return result;
}

string get_time()
{
	string reg_time;
	char local_time[32] = "";

	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	strftime(local_time, 32, "%d.%m.%Y %H:%M:%S", &tm);

	reg_time += "[";
	reg_time += local_time;
	reg_time += "] ";

	return reg_time;
}

BOOL send_message_to(string message, int choice)
{
	Sleep(300);
	// 1 - event
	// 0 - log
	DWORD  cbWritten;
	string SendMessage;

	if (choice == 0)
	{
		SendMessage += "log.";
	}
	else if (choice == 1)
	{
		SendMessage += "event.";
	}
	else if (choice == 3)
	{
		// good
		SendMessage += "file(+).";
		
	}
	else if (choice == 4)
	{
		// bad
		SendMessage += "file(-).";
	}

	SendMessage += message;
	SendMessage += "(^_^)";

	if (WriteFile(hNamedPipe, SendMessage.c_str(), SendMessage.length(), &cbWritten, NULL))
	{
		cout << get_time() << "Sent message: " << SendMessage << endl;
		cout << "Count of bytes sent: " << cbWritten << endl;

		log_file_static_analysis << get_time() << "Sent message: " << SendMessage << endl;
		log_file_static_analysis << "Count of bytes sent: " << cbWritten << endl;
		log_file_static_analysis << endl;
		return 1;
	}
	else
	{
		cout << get_time() << "Error of sending message by pipe with name '" << szPipeName << "'" << endl;

		log_file_static_analysis << get_time() << "Error of sending message by pipe with name '" << szPipeName << "'" << endl;
		log_file_static_analysis << endl;
		return 0;
	}
}

int read_and_check_integrity_db(string FileName, string Integrity)
{
	string BytesOfFile, hash;
	int count_of_signatures = 0;
	ifstream mainmdb_count(FileName);
	if (mainmdb_count.is_open())
	{
		string line;
		while (getline(mainmdb_count, line))
		{
			BytesOfFile += line;
			BytesOfFile += '\n';
			count_of_signatures++;
		}
		hash = sha256(BytesOfFile);
		//cout << hash << endl;
	}
	else
	{
		cout << get_time() << "Error: could not open file DB with name " << FileName << endl;
		log_file_static_analysis << get_time() << "Error: could not open file DB with name " << FileName << endl;
		log_file_static_analysis << endl;

		string msg_to_log;
		msg_to_log += "Error: could not open file DB with name " + FileName;
		send_message_to(msg_to_log, 0);
	}
	mainmdb_count.close();

	if (hash == Integrity)
	{
		return count_of_signatures;
	}
	else
	{
		return -1;
	}
}

void parse_and_load_virus_databases(string FolderName, string PathLevelDB)
{
	// 4566409 lines of signatures
	// count the number of lines in files mdb, hdb, hsb, ndb, fp
	string FileName,
	HexSHA256mainmdb, HexSHA256mainhdb, HexSHA256mainhsb, HexSHA256mainndb, HexSHA256mainfp;
	unsigned long
	count_of_mainmdb = 0, count_of_mainhdb = 0, count_of_mainhsb = 0,  count_of_mainndb = 0, count_of_mainfp = 0;
	
	
	// check of files integrity
	/*
	FileName = FolderName + "check_integrity.txt";
	ifstream FileIntegrity(FileName);
	if (FileIntegrity.is_open())
	{
		string line;
		while (getline(FileIntegrity, line))
		{
			string NameFile, SizeFile, HexSHA256;
			smatch match;

			regex regularmdb("([\\w-\.\\w-]+)""(:)""([\\d-]+)""(:)""([\\w-]+)");
			regex_search(line, match, regularmdb);

			NameFile += match[1];
			SizeFile += match[3];
			HexSHA256 += match[5];

			if (match.size() == 6)
			{
				if (NameFile == "main.mdb")
				{
					HexSHA256mainmdb += HexSHA256;
				}
				else if (NameFile == "main.hdb")
				{
					HexSHA256mainhdb += HexSHA256;
				}
				else if (NameFile == "main.hsb")
				{
					HexSHA256mainhsb += HexSHA256;
				}
				else if (NameFile == "main.ndb")
				{
					HexSHA256mainndb += HexSHA256;
				}
				else if (NameFile == "main.fp")
				{
					HexSHA256mainfp += HexSHA256;
				}
				else
				{
					cout << get_time() << "Error: Unknown name " << FileName << " of ClamAV DB in check_integrity.txt" << endl;
					log_file_static_analysis << get_time() << "Error: Unknown name " << FileName << " of ClamAV DB in check_integrity.txt" << endl;
					log_file_static_analysis << endl;

					string msg_to_log;
					msg_to_log += "Error: Unknown name " + FileName + " of ClamAV DB in check_integrity.txt";
					send_message_to(msg_to_log, 0);
				}
			}
			else
			{
				cout << get_time() << "Error: The file " << FileName << " is damaged"  << endl;
				log_file_static_analysis << get_time() << "Error: The file " << FileName << " is damaged" << endl;
				log_file_static_analysis << endl;

				string msg_to_log;
				msg_to_log += "Error: The file " + FileName + " is damaged";
				send_message_to(msg_to_log, 0);
			}	
		}
	}
	else
	{
		cout << get_time() << "Error: Could not open file: " << FileName << endl;
		log_file_static_analysis << get_time() << "Error: Could not open file: " << FileName << endl;
		log_file_static_analysis << endl;

		string msg_to_log;
		msg_to_log += "Error: Could not open file: " + FileName;
		send_message_to(msg_to_log, 0);
	}
	FileIntegrity.close();
	FileName.clear();
	*/


	// calculate size of databases, check their integrity and create new databases
	/*
	FileName = FolderName + "main.hdb";
	count_of_mainhdb = read_and_check_integrity_db(FileName, HexSHA256mainhdb);
	if (count_of_mainhdb == -1)
	{
		cout << get_time() << "The file " << FileName << " is damaged" << endl;
		log_file_static_analysis << get_time() << "The file " << FileName << " is damaged" << endl;
		log_file_static_analysis << endl;

		string msg_to_log;
		msg_to_log += "The file " + FileName + " is damaged";
		send_message_to(msg_to_log, 0);
	}
	else
	{
		cout << get_time() << "The file " << FileName << " passed integrity check" << endl;
		log_file_static_analysis << get_time() << "The file " << FileName << " passed integrity check" << endl;
		log_file_static_analysis << endl;

		string msg_to_log;
		msg_to_log += "The file " + FileName + " passed integrity check";
		send_message_to(msg_to_log, 0);
	}
	FileName.clear();

	FileName = FolderName + "main.hsb";
	count_of_mainhsb = read_and_check_integrity_db(FileName, HexSHA256mainhsb);
	if (count_of_mainhsb == -1)
	{
		cout << get_time() << "The file " << FileName << " is damaged" << endl;
		log_file_static_analysis << get_time() << "The file " << FileName << " is damaged" << endl;
		log_file_static_analysis << endl;

		string msg_to_log;
		msg_to_log += "The file " + FileName + " is damaged";
		send_message_to(msg_to_log, 0);
	}
	else
	{
		cout << get_time() << "The file " << FileName << " passed integrity check" << endl;
		log_file_static_analysis << get_time() << "The file " << FileName << " passed integrity check" << endl;
		log_file_static_analysis << endl;

		string msg_to_log;
		msg_to_log += "The file " + FileName + " passed integrity check";
		send_message_to(msg_to_log, 0);
	}
	FileName.clear();
	
	FileName = FolderName + "main.fp";
	count_of_mainfp = read_and_check_integrity_db(FileName, HexSHA256mainfp);
	if (count_of_mainfp == -1)
	{
		cout << get_time() << "The file " << FileName << " is damaged" << endl;
		log_file_static_analysis << get_time() << "The file " << FileName << " is damaged" << endl;
		log_file_static_analysis << endl;

		string msg_to_log;
		msg_to_log += "The file " + FileName + " is damaged";
		send_message_to(msg_to_log, 0);
	}
	else
	{
		cout << get_time() << "The file " << FileName << " passed integrity check" << endl;
		log_file_static_analysis << get_time() << "The file " << FileName << " passed integrity check" << endl;
		log_file_static_analysis << endl;

		string msg_to_log;
		msg_to_log += "The file " + FileName + " passed integrity check";
		send_message_to(msg_to_log, 0);
	}
	FileName.clear();

	*/

	/*
	FileName = FolderName + "main.mdb";
	count_of_mainmdb = read_and_check_integrity_db(FileName, HexSHA256mainmdb);
	if (count_of_mainmdb == -1)
	{
		cout << get_time() << "The file " << FileName <<  " is damaged" << endl;
		log_file_static_analysis << get_time() << "The file " << FileName << " is damaged" << endl;
		log_file_static_analysis << endl;
	}
	else
	{
		cout << get_time() << "The file " << FileName << " passed integrity check" << endl;
		log_file_static_analysis << get_time() << "The file " << FileName << " passed integrity check" << endl;
		log_file_static_analysis << endl;
	}
	FileName.clear();

	FileName = FolderName + "main.ndb";
	count_of_mainndb = read_and_check_integrity_db(FileName, HexSHA256mainndb);
	if (count_of_mainndb == -1)
	{
		cout << get_time() << "The file " << FileName << " is damaged" << endl;
		log_file_static_analysis << get_time() << "The file " << FileName << " is damaged" << endl;
		log_file_static_analysis << endl;
	}
	else
	{
		cout << get_time() << "The file " << FileName << " passed integrity check" << endl;
		log_file_static_analysis << get_time() << "The file " << FileName << " passed integrity check" << endl;
		log_file_static_analysis << endl;
	}
	FileName.clear();
	*/
	/*
	FileName = FolderName + "main.mdb";
	ifstream mainmdb(FileName);
	if (mainmdb.is_open())
	{
		string line;
		while (getline(mainmdb, line))
		{
			string PESectionSize, PESectionHash, MalwareName;
			smatch match;

			regex regularmdb("([\\d-]+)""(:)""([\\w-]+)""(:)");
			regex_search(line, match, regularmdb);
			
			PESectionSize += match[1];
			PESectionHash += match[3];
			MalwareName += match.suffix();
		}
	}
	else
	{
		cout << "Error of openning " << FileName << endl;
	}
	mainmdb.close();
	FileName.clear();
	*/

	// open the leveldb databases, if they do not exist, then parse the database from clamav, create our own leveldb databases and fill them
	leveldb::WriteOptions writeOptions;

	string leveldb_hdb = "DB_hdb";
	options_hdb.create_if_missing = false;
	leveldb::Status status_hdb = leveldb::DB::Open(options_hdb, PathLevelDB + leveldb_hdb, &db_hdb);
	if (false == status_hdb.ok())
	{
		cout << get_time() << "Error: Unable to open/create database" << PathLevelDB + leveldb_hdb;
		cout << ". Status: " << status_hdb.ToString();
		cout << ". Try to create database " << PathLevelDB + leveldb_hdb << endl;
		log_file_static_analysis << get_time() << "Error: Unable to open/create database" << PathLevelDB + leveldb_hdb;
		log_file_static_analysis << ". Status: " << status_hdb.ToString();
		log_file_static_analysis << ". Try to create database " << PathLevelDB + leveldb_hdb << endl;
		log_file_static_analysis << endl;

		string msg_to_log;
		msg_to_log += "Error: Unable to open/create database" + PathLevelDB + leveldb_hdb;
		msg_to_log += ". Status: " + status_hdb.ToString();
		msg_to_log += ". Try to create database " + PathLevelDB + leveldb_hdb;
		send_message_to(msg_to_log, 0);
		
		options_hdb.create_if_missing = true;
		leveldb::Status status_hdb = leveldb::DB::Open(options_hdb, PathLevelDB + leveldb_hdb, &db_hdb);
		
		int flag = 0;
		FileName = FolderName + "main.hdb";
		ifstream mainhdb(FileName);
		if (mainhdb.is_open())
		{
			string line;
			while (getline(mainhdb, line))
			{
				string FileSize, HashString, MalwareName;
				smatch match;

				regex regularmdb("([\\w-]+)""(:)""([\\d-]+)""(:)");
				regex_search(line, match, regularmdb);

				HashString += match[1];
				FileSize += match[3];
				MalwareName += match.suffix();

				status_hdb = db_hdb->Put(leveldb::WriteOptions(), HashString, MalwareName);
				if (false == status_hdb.ok())
				{
					cout << get_time() << "Error of putting key-value: " << HashString << '-' << MalwareName << " in " << FileName << endl;
					log_file_static_analysis << get_time() << "Error of putting key-value: " << HashString << '-' << MalwareName << " in " << FileName << endl;
					log_file_static_analysis << endl;
					
					string msg_to_log_temp;
					msg_to_log_temp += "Error of putting key-value: " + HashString + '-' + MalwareName + " in " + FileName;
					send_message_to(msg_to_log_temp, 0);
				}		
			}
			mainhdb.close();
			flag = 1;
		}
		else
		{
			cout << get_time() << "Error of openning " << FileName << endl;
			log_file_static_analysis << get_time() << "Error of openning " << FileName << endl;
			log_file_static_analysis << endl;

			string msg_to_log;
			msg_to_log += "Error of openning " + FileName;
			send_message_to(msg_to_log, 0);
		}
		if (flag == 1)
		{
			cout << get_time() << "Database " << PathLevelDB + leveldb_hdb << " successfully created" << endl;
			log_file_static_analysis << get_time() << "Database " << PathLevelDB + leveldb_hdb << " successfully created" << endl;
			log_file_static_analysis << endl;

			string msg_to_log;
			msg_to_log += "Database " + PathLevelDB + leveldb_hdb + " successfully created";
			send_message_to(msg_to_log, 0);
		}
	}
	else
	{
		// database was openned
	}		
	FileName.clear();
	
	string leveldb_hsb = "DB_hsb";
	options_hsb.create_if_missing = false;
	leveldb::Status status_hsb = leveldb::DB::Open(options_hsb, PathLevelDB + leveldb_hsb, &db_hsb);
	if (false == status_hsb.ok())
	{
		cout << get_time() << "Unable to open/create database " << PathLevelDB + leveldb_hsb;
		cout << ". Status: " << status_hsb.ToString();
		cout << ". Try to create database " << PathLevelDB + leveldb_hsb << endl;
		log_file_static_analysis << get_time() << "Unable to open/create database " << PathLevelDB + leveldb_hsb;
		log_file_static_analysis << ". Status: " << status_hsb.ToString();
		log_file_static_analysis << ". Try to create database " << PathLevelDB + leveldb_hsb << endl;
		log_file_static_analysis << endl;

		string msg_to_log;
		msg_to_log += "Unable to open/create database " + PathLevelDB + leveldb_hsb;
		msg_to_log += ". Status: " + status_hsb.ToString();
		msg_to_log += ". Try to create database " + PathLevelDB + leveldb_hsb;
		send_message_to(msg_to_log, 0);

		options_hsb.create_if_missing = true;
		leveldb::Status status_hsb = leveldb::DB::Open(options_hsb, PathLevelDB + leveldb_hsb, &db_hsb);

		int flag = 0;
		FileName = FolderName + "main.hsb";
		ifstream mainhsb(FileName);
		if (mainhsb.is_open())
		{
			string line;
			while (getline(mainhsb, line))
			{
				string FileSize, HashString, tmp, MalwareName, lastnum73;
				smatch match, matchtmp;

				regex regularmdb("([\\w-]+)""(:)""([\\w-]+)""(:)");
				regex_search(line, match, regularmdb);

				HashString += match[1];
				FileSize += match[3];
				tmp += match.suffix();

				regex regulartmp("(:)");
				if (regex_search(tmp, matchtmp, regulartmp) == true)
				{
					MalwareName += matchtmp.prefix();
					lastnum73 += matchtmp.suffix();
				}
				else
				{
					MalwareName += tmp;
				}

				status_hsb = db_hsb->Put(leveldb::WriteOptions(), HashString, MalwareName);
				if (false == status_hsb.ok())
				{
					cout << get_time() << "Error of putting key-value: " << HashString << '-' << MalwareName << endl;
					log_file_static_analysis << get_time() << "Error of putting key-value: " << HashString << '-' << MalwareName << endl;
					log_file_static_analysis << endl;

					string msg_to_log_temp;
					msg_to_log_temp += "Error of putting key-value: " + HashString + '-' + MalwareName;
					send_message_to(msg_to_log_temp, 0);
				}		
			}
			mainhsb.close();
		}
		else
		{
			cout << get_time() << "Error of openning " << FileName << endl;
			log_file_static_analysis << get_time() << "Error of openning " << FileName << endl;
			log_file_static_analysis << endl;

			string msg_to_log;
			msg_to_log += "Error of openning " + FileName;
			send_message_to(msg_to_log, 0);

		}
		if (flag == 1)
		{
			cout << get_time() << "Database " << PathLevelDB + leveldb_hsb << " successfully created" << endl;
			log_file_static_analysis << get_time() << "Database " << PathLevelDB + leveldb_hsb << " successfully created" << endl;
			log_file_static_analysis << endl;

			string msg_to_log;
			msg_to_log += "Database " + PathLevelDB + leveldb_hsb + " successfully created";
			send_message_to(msg_to_log, 0);
		}
	}
	else
	{
		// database was openned
	}		
	FileName.clear();

	string leveldb_fp = "DB_fp";
	options_fp.create_if_missing = false;
	leveldb::Status status_fp = leveldb::DB::Open(options_fp, PathLevelDB + leveldb_fp, &db_fp);
	if (false == status_fp.ok())
	{
		cout << get_time() << "Error: Unable to open/create database " << PathLevelDB + leveldb_fp;
		cout << ". Status: " << status_hsb.ToString();
		cout << ". Try to create database " << PathLevelDB + leveldb_fp << endl;
		log_file_static_analysis << get_time() << "Error: Unable to open/create database " << PathLevelDB + leveldb_fp;
		log_file_static_analysis << ". Status: " << status_fp.ToString();
		log_file_static_analysis << ". Try to create database " << PathLevelDB + leveldb_fp << endl;
		log_file_static_analysis << endl;

		string msg_to_log;
		msg_to_log += "Unable to open/create database " + PathLevelDB + leveldb_fp;
		msg_to_log += ". Status: " + status_fp.ToString();
		msg_to_log += ". Try to create database " + PathLevelDB + leveldb_fp;
		send_message_to(msg_to_log, 0);

		options_fp.create_if_missing = true;
		leveldb::Status status_fp = leveldb::DB::Open(options_fp, PathLevelDB + leveldb_fp, &db_fp);

		int flag = 0;
		FileName = FolderName + "main.fp";
		ifstream mainfp(FileName);
		if (mainfp.is_open())
		{
			string line;
			while (getline(mainfp, line))
			{
				string FileSize, HashString, FileName;
				smatch match;

				regex regularfp("([\\w-]+)""(:)""([\\w-]+)""(:)");
				regex_search(line, match, regularfp);

				HashString += match[1];
				FileSize += match[3];
				FileName += match.suffix();

				status_fp = db_fp->Put(leveldb::WriteOptions(), HashString, FileName);
				if (false == status_fp.ok())
				{
					cout << get_time() << "Error of putting key-value: " << HashString << '-' << FileName << endl;
					log_file_static_analysis << get_time() << "Error of putting key-value: " << HashString << '-' << FileName << endl;
					log_file_static_analysis << endl;

					string msg_to_log_temp;
					msg_to_log_temp += "Error of putting key-value: " + HashString + '-' + FileName;
					send_message_to(msg_to_log_temp, 0);
				}	
			}
			mainfp.close();
		}
		else
		{
			cout << get_time() << "Error of openning " << FileName << endl;
			log_file_static_analysis << get_time() << "Error of openning " << FileName << endl;
			log_file_static_analysis << endl;

			string msg_to_log;
			msg_to_log += "Error of openning " + FileName;
			send_message_to(msg_to_log, 0);
		}
		if (flag == 1)
		{
			cout << get_time() << "Database " << PathLevelDB + leveldb_fp << " successfully created" << endl;
			log_file_static_analysis << get_time() << "Database " << PathLevelDB + leveldb_fp << " successfully created" << endl;
			log_file_static_analysis << endl;

			string msg_to_log;
			msg_to_log += "Database " + PathLevelDB + leveldb_fp + " successfully created";
			send_message_to(msg_to_log, 0);
		}
	}
	else
	{
		// database was openned	
	}
	FileName.clear();

	/*
	options_ndb.create_if_missing = true;
	leveldb::Status status_ndb = leveldb::DB::Open(options_ndb, "D:\\Users\\Desktop\\IBKS\\5_course_1_semester\\Zhukovsky\\Laba2\\Static_Analysis_Subsystem\\Static_Analysis_Subsystem\\MyDB\\DB_ndb", &db_ndb);
	if (false == status_ndb.ok())
	{
		cout << "Unable to open/create database 'D:\\Users\\Desktop\\IBKS\\5_course_1_semester\\Zhukovsky\\Laba2\\Static_Analysis_Subsystem\\Static_Analysis_Subsystem\\MyDB\\DB_ndb'" << endl;
		cout << status_ndb.ToString() << endl;
	}
	else
	{
		FileName = FolderName + "main.ndb";
		ifstream mainndb(FileName);
		if (mainndb.is_open())
		{
			string line;
			while (getline(mainndb, line))
			{
				string HexSignature, MalwareName, other1, other2;
				smatch match, matchtmp1, matchtmp2;

				regex regularndb("(:)""[\\d]""(:)""[^:-]+""(:)");
				regex_search(line, match, regularndb);

				HexSignature += match.suffix();
				MalwareName += match.prefix();
				other1 += match[0];

				regex regulartmp1("[^:-]+""(:)""[^:-]+");
				regex_search(other1, matchtmp1, regulartmp1);

				other2 += matchtmp1[0];

				string TargetType, Offset;
				regex regulartmp2("(:)");
				regex_search(other2, matchtmp2, regulartmp2);

				TargetType += matchtmp2.prefix();
				Offset += matchtmp2.suffix();

				status_ndb = db_ndb->Put(leveldb::WriteOptions(), HexSignature, MalwareName);
				if (false == status_hsb.ok())
					cout << "Error of putting key-value: " << HexSignature << '-' << MalwareName << endl;
			}
			mainndb.close();
		}
		else
		{
			cout << "Error of openning " << FileName << endl;
		}
	}
	FileName.clear();
	*/
}

int scan_by_signature(string file_hash_md5)
{
	leveldb::Status local_status;
	string MalwareNamehdb, MalwareNamehsb, FileNamefp;
	
	local_status = db_hdb->Get(leveldb::ReadOptions(), file_hash_md5, &MalwareNamehdb);
	if (!local_status.ok())
	{
		cout << local_status.ToString() << endl;
	}
	else
	{
		cout << get_time() << "ALERT!!! Detected " << MalwareNamehdb << endl;
		log_file_static_analysis << get_time() << "ALERT!!! Detected " << MalwareNamehdb << endl;
		log_file_static_analysis << endl;

		string message = "ALERT!!! Detected malware with name '" + MalwareNamehdb + ". You can check log file 'log_static_analysis.txt'";
		send_message_to(message, 1);
		return 1;
	}

	local_status = db_hsb->Get(leveldb::ReadOptions(), file_hash_md5, &MalwareNamehsb);
	if (!local_status.ok())
	{
		cout << local_status.ToString() << endl;
	}	
	else
	{
		cout << get_time() << "ALERT!!! Detected " << MalwareNamehsb << endl;
		log_file_static_analysis << get_time() << "ALERT!!! Detected " << MalwareNamehsb << endl;
		log_file_static_analysis << endl;

		string message = "ALERT!!! Detected malware with name '" + MalwareNamehsb + ". You can check log file 'log_static_analysis.txt'";
		send_message_to(message, 1);
		return 1;
	}	

	local_status = db_fp->Get(leveldb::ReadOptions(), file_hash_md5, &FileNamefp);
	if (!local_status.ok())
	{
		cout << local_status.ToString() << endl;
	}
	else
	{
		cout << get_time() << "ALERT!!! Detected " << FileNamefp << endl;
		log_file_static_analysis << get_time() << "ALERT!!! Detected " << FileNamefp << endl;
		log_file_static_analysis << endl;

		string message = "ALERT!!! Detected malware with name '" + FileNamefp + ". You can check log file 'log_static_analysis.txt'";
		send_message_to(message, 1);
		return 1;
	}
	return 0;
}

int load_yara_rules_for_malware(string PathYaraRules)
{
	// add yara rules
	// all rules files must be in one folder
	int flag = 0;
	WIN32_FIND_DATA fd;
	string temp = PathYaraRules + "\\*.*";
	HANDLE hFind = FindFirstFile(&temp[0], &fd);
	if (hFind != INVALID_HANDLE_VALUE)
	{
		do {
			if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				if (strncmp(fd.cFileName, "$RECYCLE.BIN", sizeof("$RECYCLE.BIN")) &&
					strncmp(fd.cFileName, ".", sizeof(".")) &&
					strncmp(fd.cFileName, "..", sizeof("..")))
				{
					// do nothing
				}

			}
			else
			{
				// its file
				smatch match;
				string FileName;
				FileName += fd.cFileName;

				regex regular("\\.");
				regex_search(FileName, match, regular);

				if (match.suffix() == "yar")
				{
					// its .yar
					string NewFileName = PathYaraRules + "\\" + FileName;
					yara_for_malware.addRuleFile(NewFileName);
					flag = 1;
				}
			}
		} while (::FindNextFile(hFind, &fd));
		::FindClose(hFind);
		cout << get_time() << "Yara rules for malware loaded successfully" << endl;
		log_file_static_analysis << get_time() << "Yara rules for malware loaded successfully" << endl;
		log_file_static_analysis << endl;

		/*
		string msg_to_log;
		msg_to_log += "Yara rules for malware loaded successfully";
		send_message_to(msg_to_log, 0);
		*/
		return 1;
	}
	else
	{
		return 0;
	}
}

int scan_by_yara_rules(string FName)
{
	if (yara_for_malware.analyze(FName))
	{
		vector<yaracpp::YaraRule> matched_rules = yara_for_malware.getDetectedRules();
		cout << "Total Rules Matched: " << matched_rules.size() << "\n";

		vector<yaracpp::YaraRule> unmatched_rules = yara_for_malware.getUndetectedRules();
		cout << "Total Rules Un-matched: " << unmatched_rules.size() << "\n\n";

		if (matched_rules.size() != 0)
		{
			string msg_to_log;
			string message = "ALERT!!! Detected yara-rules for file '" + FName + ". You can check log file 'log_static_analysis.txt'";
			send_message_to(message, 1);

			cout << get_time() << "ALERT!!! Matched yara rules of MALWARE for " << FName << " file. ";
			log_file_static_analysis << get_time() << "ALERT!!! Matched yara rules of MALWARE for " << FName << " file. ";

			msg_to_log += "ALERT!!! Matched yara rules of MALWARE for " + FName + " file. ";

			for (yaracpp::YaraRule rule : matched_rules)
			{
				cout << "Matched Rule Name: " << rule.getName() << ". ";
				cout << "Meta Information Count: " << rule.getNumberOfMetas() << ". ";
				log_file_static_analysis << "Matched Rule Name: " << rule.getName() << ". ";
				log_file_static_analysis << "Meta Information Count: " << rule.getNumberOfMetas() << ". ";

				msg_to_log += "Matched Rule Name: " + rule.getName() + ". ";
				msg_to_log += "Meta Information Count: " + to_string(rule.getNumberOfMetas()) + ". ";

				cout << "META INFOMATIONS: ";
				log_file_static_analysis << "META INFOMATIONS: ";

				msg_to_log += "META INFOMATIONS: ";
				vector<yaracpp::YaraMeta> meta_informations = rule.getMetas();
				for (yaracpp::YaraMeta meta : meta_informations)
				{
					cout << meta.getId() << " : " << meta.getStringValue() << "; ";
					log_file_static_analysis << meta.getId() << " : " << meta.getStringValue() << "; ";

					msg_to_log += meta.getId() + " : " + meta.getStringValue() + "; ";
				}
			}
			log_file_static_analysis << endl << endl;
			send_message_to(msg_to_log, 0);
			return 1;
		}
		else
		{
			// don't match yara rules for file
			return 0;
		}
	}
	else
	{
		cout << get_time() << "Error of call function 'yara.analyze(FName)' in scan_by_yara_rules()" << endl;
		log_file_static_analysis << get_time() << "Error of call function 'yara.analyze(FName)' in scan_by_yara_rules()" << endl;
		log_file_static_analysis << endl;

		string msg_to_log;
		msg_to_log += "Error of call function 'yara.analyze(FName)' in scan_by_yara_rules()";
		send_message_to(msg_to_log, 0);
		return 0;
	}
}

int load_yara_rules_for_packer(string PathYaraRules)
{
	// add yara rules
	// all rules files must be in one folder
	WIN32_FIND_DATA fd;
	string temp = PathYaraRules + "\\*.*";
	HANDLE hFind = FindFirstFile(&temp[0], &fd);
	if (hFind != INVALID_HANDLE_VALUE)
	{
		do {
			if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				if (strncmp(fd.cFileName, "$RECYCLE.BIN", sizeof("$RECYCLE.BIN")) &&
					strncmp(fd.cFileName, ".", sizeof(".")) &&
					strncmp(fd.cFileName, "..", sizeof("..")))
				{
					// do nothing
				}
			}
			else
			{
				// its file
				smatch match;
				string FileName;
				FileName += fd.cFileName;

				regex regular("\\.");
				regex_search(FileName, match, regular);

				if (match.suffix() == "yar" || match.suffix() == "yara")
				{
					// its .yar
					string NewFileName = PathYaraRules + "\\" + FileName;
					yara_for_packer.addRuleFile(NewFileName);
				}
			}

		} while (::FindNextFile(hFind, &fd));
		::FindClose(hFind);
		cout << get_time() << "Yara rules for packer loaded successfully" << endl;
		log_file_static_analysis << get_time() << "Yara rules for packer loaded successfully" << endl;
		log_file_static_analysis << endl;
		
		/*
		string msg_to_log;
		msg_to_log += "Yara rules for packer loaded successfully";
		send_message_to(msg_to_log, 0);
		*/
		return 1;
	}
	else
	{
		return 0;
	}
}

int identify_packer_by_yara_rules(string FName)
{
	// analyze target file
	if (yara_for_packer.analyze(FName))
	{
		vector<yaracpp::YaraRule> matched_rules = yara_for_packer.getDetectedRules();
		cout << "Total Rules Matched: " << matched_rules.size() << "\n";

		vector<yaracpp::YaraRule> unmatched_rules = yara_for_packer.getUndetectedRules();
		cout << "Total Rules Un-matched: " << unmatched_rules.size() << "\n\n";
		if (matched_rules.size() != 0)
		{
			string msg_to_log;
			string message = "Detected yara-rules of packer detection for file '" + FName + ". You can check log file 'log_static_analysis.txt'";
			send_message_to(message, 1);
			cout << get_time() << "Matched yara rules of PACKER for " << FName << " file. ";
			log_file_static_analysis << get_time() << "Matched yara rules of PACKER for " << FName << " file. ";

			msg_to_log += "Matched yara rules of PACKER for " + FName + " file. ";

			for (yaracpp::YaraRule rule : matched_rules)
			{
				cout << "Matched Rule Name: " << rule.getName() << ". ";
				cout << "Meta Information Count: " << rule.getNumberOfMetas() << ". ";
				log_file_static_analysis << get_time() << "Matched Rule Name: " << rule.getName() << ". ";
				log_file_static_analysis << "Meta Information Count: " << rule.getNumberOfMetas() << ". ";

				msg_to_log += "Matched Rule Name: " + rule.getName() + ". ";
				msg_to_log += "Meta Information Count: " + to_string(rule.getNumberOfMetas()) + ". ";

				// PRINT THE META INFORMATIONS
				cout << "META INFOMATIONS: ";
				log_file_static_analysis << "META INFOMATIONS: ";

				msg_to_log += "META INFOMATIONS: ";

				vector<yaracpp::YaraMeta> meta_informations = rule.getMetas();
				for (yaracpp::YaraMeta meta : meta_informations)
				{
					cout << meta.getId() << " : " << meta.getStringValue() << "; ";
					log_file_static_analysis << meta.getId() << " : " << meta.getStringValue() << "; ";

					msg_to_log += meta.getId() + " : " + meta.getStringValue() + "; ";
				}
			}
			log_file_static_analysis << endl << endl;
			send_message_to(msg_to_log, 0);
			return 1;
		}
		else
		{
			// don't match yara rules for file
			return 0;
		}
	}
	else
	{
		cout << get_time() << "Error of call function 'yara.analyze(FName)' in identify_packer_by_yara_rules()" << endl;
		log_file_static_analysis << get_time() << "Error of call function 'yara.analyze(FName)' in identify_packer_by_yara_rules()" << endl;
		log_file_static_analysis << endl;

		string msg_to_log;
		msg_to_log += "Error of call function 'yara.analyze(FName)' in identify_packer_by_yara_rules()";
		send_message_to(msg_to_log, 0);
		return 0;
	}
}

BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile)
{
	LONG lStatus;
	DWORD dwLastError;

	// Initialize the WINTRUST_FILE_INFO structure.
	WINTRUST_FILE_INFO FileData;
	memset(&FileData, 0, sizeof(FileData));
	FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
	FileData.pcwszFilePath = pwszSourceFile;
	FileData.hFile = NULL;
	FileData.pgKnownSubject = NULL;

	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WinTrustData;

	// Initialize the WinVerifyTrust input data structure.

	// Default all fields to 0.
	memset(&WinTrustData, 0, sizeof(WinTrustData));

	WinTrustData.cbStruct = sizeof(WinTrustData);

	// Use default code signing EKU.
	WinTrustData.pPolicyCallbackData = NULL;

	// No data to pass to SIP.
	WinTrustData.pSIPClientData = NULL;

	// Disable WVT UI.
	WinTrustData.dwUIChoice = WTD_UI_NONE;

	// No revocation checking.
	WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

	// Verify an embedded signature on a file.
	WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

	// Verify action.
	WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

	// Verification sets this value.
	WinTrustData.hWVTStateData = NULL;

	// Not used.
	WinTrustData.pwszURLReference = NULL;

	// This is not applicable if there is no UI because it changes 
	// the UI to accommodate running applications instead of 
	// installing applications.
	WinTrustData.dwUIContext = 0;

	// Set pFile.
	WinTrustData.pFile = &FileData;

	// WinVerifyTrust verifies signatures as specified by the GUID 
	// and Wintrust_Data.
	lStatus = WinVerifyTrust(NULL,&WVTPolicyGUID, &WinTrustData);

	string msg_to_log;

	switch (lStatus)
	{
	case ERROR_SUCCESS:
		/*
		Signed file:
			- Hash that represents the subject is trusted.

			- Trusted publisher without any verification errors.

			- UI was disabled in dwUIChoice. No publisher or
				time stamp chain errors.

			- UI was enabled in dwUIChoice and the user clicked
				"Yes" when asked to install and run the signed
				subject.
		*/
		wprintf_s(L"The file \"%s\" is signed and the signature " L"was verified.\n", pwszSourceFile);
		log_file_static_analysis << get_time() << "The file '" << wchar_to_char(pwszSourceFile) << "' is signed and the signature was verified.\n";
		msg_to_log += "The file '";
		msg_to_log += wchar_to_char(pwszSourceFile);
		msg_to_log += "' is signed and the signature was verified.";
		break;

	case TRUST_E_NOSIGNATURE:
		// The file was not signed or had a signature 
		// that was not valid.

		// Get the reason for no signature.
		dwLastError = GetLastError();
		if (TRUST_E_NOSIGNATURE == dwLastError || TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError || TRUST_E_PROVIDER_UNKNOWN == dwLastError)
		{
			// The file was not signed.
			wprintf_s(L"The file \"%s\" is not signed.\n", pwszSourceFile);
			log_file_static_analysis << get_time() << "The file '" << wchar_to_char(pwszSourceFile) << "' is not signed.\n";
			msg_to_log += "The file '";
			msg_to_log += wchar_to_char(pwszSourceFile);
			msg_to_log += "' is not signed.";
		}
		else
		{
			// The signature was not valid or there was an error 
			// opening the file.
			wprintf_s(L"An unknown error occurred trying to " L"verify the signature of the \"%s\" file.\n", pwszSourceFile);
			log_file_static_analysis << get_time() << "An unknown error occurred trying to verify the signature of the '" << wchar_to_char(pwszSourceFile) << "' file.\n";
			msg_to_log += "An unknown error occurred trying to verify the signature of the '";
			msg_to_log += wchar_to_char(pwszSourceFile);
			msg_to_log += "' file.";
		}
		break;

	case TRUST_E_EXPLICIT_DISTRUST:
		// The hash that represents the subject or the publisher 
		// is not allowed by the admin or user.
		wprintf_s(L"The signature is present, but specifically " L"disallowed.\n");
		log_file_static_analysis << get_time() << "The signature of the '" << wchar_to_char(pwszSourceFile) << "' is present, but specifically disallowed.\n";
		msg_to_log += "The signature of the '";
		msg_to_log += wchar_to_char(pwszSourceFile);
		msg_to_log += "' is present, but specifically disallowed.";
		break;

	case TRUST_E_SUBJECT_NOT_TRUSTED:
		// The user clicked "No" when asked to install and run.
		wprintf_s(L"The signature is present, but not " L"trusted.\n");
		log_file_static_analysis << get_time() << "The signature of the '" << wchar_to_char(pwszSourceFile) << "' is present, but not trusted.\n";
		msg_to_log += "The signature of the '";
		msg_to_log += wchar_to_char(pwszSourceFile);
		msg_to_log += "' is present, but not trusted.";
		break;

	case CRYPT_E_SECURITY_SETTINGS:
		/*
		The hash that represents the subject or the publisher
		was not explicitly trusted by the admin and the
		admin policy has disabled user trust. No signature,
		publisher or time stamp errors.
		*/
		wprintf_s(L"CRYPT_E_SECURITY_SETTINGS - The hash "
			L"representing the subject or the publisher wasn't "
			L"explicitly trusted by the admin and admin policy "
			L"has disabled user trust. No signature, publisher "
			L" ");
		log_file_static_analysis << get_time() << wchar_to_char(pwszSourceFile) << ". CRYPT_E_SECURITY_SETTINGS - The hash representing the subject or the publisher wasn't explicitly trusted by the admin and admin policy has disabled user trust. No signature, publisher or timestamp errors.\n";
		msg_to_log += wchar_to_char(pwszSourceFile);
		msg_to_log += ". CRYPT_E_SECURITY_SETTINGS - The hash representing the subject or the publisher wasn't explicitly trusted by the admin and admin policy has disabled user trust. No signature, publisher or timestamp errors.";
		break;

	default:
		// The UI was disabled in dwUIChoice or the admin policy 
		// has disabled user trust. lStatus contains the 
		// publisher or time stamp chain error.
		wprintf_s(L"Error is: 0x%x.\n", lStatus);

		ostringstream oss;
		oss << lStatus;
		log_file_static_analysis << get_time() << "Error of checking signature of the '" << wchar_to_char(pwszSourceFile) << "'. Error is: " << oss.str() << endl;
		msg_to_log += "Error of checking signature of the '"; 
		msg_to_log += wchar_to_char(pwszSourceFile);
		msg_to_log += "'. Error is: ";
		msg_to_log += oss.str();
		msg_to_log += '.';
		break;
	}

	log_file_static_analysis << endl;

	// Any hWVTStateData must be released by a call with close.
	WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

	lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);
	
	send_message_to(msg_to_log, 0);
	string message = "File Signature Verification has completed. You can check results in log file 'log_static_analysis.txt'";
	send_message_to(message, 1);

	return true;
}

void FindFiles(string FName, int choice)
{
	if ((FILE_ATTRIBUTE_DIRECTORY & GetFileAttributes(FName.c_str())) == FILE_ATTRIBUTE_DIRECTORY)
	{
		//directory
		WIN32_FIND_DATA fd;
		string temp = FName + "\\*.*";
		HANDLE hFind = FindFirstFile(&temp[0], &fd);
		if (hFind != INVALID_HANDLE_VALUE)
		{
			do {
				if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					if (strncmp(fd.cFileName, "$RECYCLE.BIN", sizeof("$RECYCLE.BIN")) &&
						strncmp(fd.cFileName, ".", sizeof(".")) &&
						strncmp(fd.cFileName, "..", sizeof("..")))
					{
						printf("%s: %s\n", (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "Folder" : "File", fd.cFileName);
						string NewFolderName = FName + "\\" + fd.cFileName;
						FindFiles(NewFolderName, choice);
					}
				}
				else
				{
					printf("%s: %s\n", (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "Folder" : "File", fd.cFileName);			
					string NewFileName = FName + "\\" + fd.cFileName;

					//scan
					if (choice == 1)
					{
						int res = scan_by_signature(get_md5_from_file(NewFileName));
						if (res == 1)
							send_message_to(NewFileName, 4);
						else if (res == 0)
							send_message_to(NewFileName, 3);
					}
					else if (choice == 2)
					{
						int res = scan_by_yara_rules(NewFileName);
						if (res == 1)
							send_message_to(NewFileName, 4);
						else if (res == 0)
							send_message_to(NewFileName, 3);
					}
					else if (choice == 3)
					{
						identify_packer_by_yara_rules(NewFileName);
					}
					else if (choice == 4)
					{
						VerifyEmbeddedSignature(char_to_wchat_t(NewFileName.c_str()));
					}
				}
			} while (::FindNextFile(hFind, &fd));

			::FindClose(hFind);
		}
	}
	else
	{
		//scan
		if (choice == 1)
		{
			int res = scan_by_signature(get_md5_from_file(FName));
			if (res == 1)
				send_message_to(FName, 4);
			else if (res == 0)
				send_message_to(FName, 3);
		}
		else if (choice == 2)
		{
			int res = scan_by_yara_rules(FName);
			if (res == 1)
				send_message_to(FName, 4);
			else if (res == 0)
				send_message_to(FName, 3);
		}
		else if (choice == 3)
		{
			identify_packer_by_yara_rules(FName);
		}
		else if (choice == 4)
		{
			VerifyEmbeddedSignature(char_to_wchat_t(FName.c_str()));
		}
	}
}

void main(int argc, char* argv[])
{
	/*
	functions:
	1. -s path_dir_or_file		check files for signature matches
	2. -y path_dir_or_file		check files for yara-rules
	3. -p path_dir_or_file		define file packing
	4. -v path_dir_or_file		 file signature verification

	sha256 and md5 files:
	get_sha256_from_file("D:\\Users\\Desktop\\IBKS\\5_course_1_semester\\Zhukovsky\\Laba2\\TestFiles\\gg.pdf");
	get_md5_from_file("D:\\Users\\Desktop\\IBKS\\5_course_1_semester\\Zhukovsky\\Laba2\\TestFiles\\gg.pdf");

	directory with test files: D:\Users\Desktop\dir_file

	filename for signature verification test: D:\Programs\Python\Python37_64\python3.exe
	*/
	
	int choice;
	string FName;

	// path to ClamAV databases
	string PathDataBases = "C:\\UnterAV\\DataBases\\ClamavSignatureDataBase\\maincvd\\";
	// path to databases with signatures stored in LevelDB
	string PathLevelDB = "C:\\UnterAV\\DataBases\\LevelDB\\MalwareDB\\";
	// path to Yara rules for malwares
	string PathYaraRulesForScanningMalware = "C:\\UnterAV\\Rules\\YaraRules\\ForMalware";
	// path to Yara rules for packing definition
	string PathYaraRulesForPackers = "C:\\UnterAV\\Rules\\YaraRules\\ForPackers";

	log_file_static_analysis.open("C:\\UnterAV\\Logs\\log_static_analysis.txt", ios::app);

	// Create a pipe with the PIPES process
	hNamedPipe = CreateFile(szPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

	// If an error occurs, display its code and exit the application
	if (hNamedPipe == INVALID_HANDLE_VALUE)
	{
		fprintf(stdout, "CreateFile: Error %ld\n", GetLastError());
		return;
	}
	// Displaying a message about channel creation
	fprintf(stdout, "\nConnected. Type 'exit' to terminate\n");

	if (!strncmp(argv[1], "-s", 2)) {
		FName = argv[2];
		choice = 1;
		// 1. -s path_dir_or_file
		// checking files for signature matches	
		// parsing clamav databases, creating leveldb databases, checking integrity
		parse_and_load_virus_databases(PathDataBases, PathLevelDB);

		// recursive iteration over all files/directories
		FindFiles(FName, choice);
	}
	else if (!strncmp(argv[1], "-y", 2)) {
		FName = argv[2];
		choice = 2;
		// 2. -y path_dir_or_file
		// checking files for yara-rules
		if (load_yara_rules_for_malware(PathYaraRulesForScanningMalware) == 1)
		{
			FindFiles(FName, choice);
		}
		else
		{
			cout << get_time() << "Error of loading yara rules of MALWARE" << endl;
			log_file_static_analysis << get_time() << "Error of loading yara rules MALWARE" << endl;
			log_file_static_analysis << endl;

			string msg_to_log;
			msg_to_log += "Error of loading yara rules of MALWARE";
			send_message_to(msg_to_log, 0);

		}
	}
	else if (!strncmp(argv[1], "-p", 2)) {
		FName = argv[2];
		choice = 3;
		// 3. -p path_dir_or_file
		// file packaging definition
		if (load_yara_rules_for_packer(PathYaraRulesForPackers) == 1)
		{
			FindFiles(FName, choice);
		}
		else
		{
			cout << get_time() << "Error of loading yara rules of PACKER" << endl;
			log_file_static_analysis << get_time() << "Error of loading yara rules of PACKER" << endl;
			log_file_static_analysis << endl;
			
			string msg_to_log;
			msg_to_log += "Error of loading yara rules of PACKER";
			send_message_to(msg_to_log, 0);
		}
	}
	else if (!strncmp(argv[1], "-v", 2)) {
		FName = argv[2];
		choice = 4;
		// 4. -v path_dir_or_file
		// file signature verification
		FindFiles(FName, choice);
	}

	// close databases LevelDB
	if (db_hdb)
		delete db_hdb;
	if (db_hsb)
		delete db_hsb;
	if (db_fp)
		delete db_fp;

	// close the log file
	log_file_static_analysis.close();

	if (hNamedPipe)
		CloseHandle(hNamedPipe);
}
