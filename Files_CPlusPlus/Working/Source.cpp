
#include <iostream>
#include <string>
#include <iomanip>
#include <fstream>

using namespace std;

#define DEBUG

#define MAXLEN 10	//the 10th character is a NULL, max length is 9

struct UserInfo {
	char userID[MAXLEN];
	char password[MAXLEN];
};


class SaveInformation {
	char hash[MAXLEN] = {0xf,1,0xf,3,0xf,5,0xf,0xf,7};
	UserInfo InputInfo = { "", "" };
	UserInfo ValidIdPw[MAXLEN * 2]; 
	int NextIndex = 0;						

public:
	SaveInformation(); //default
	~SaveInformation();//destructor
	void Mangle(UserInfo temp);
	UserInfo UnMangle(int index);
	int ReadID(UserInfo &temp);
	int ReadPW(UserInfo &temp);
	bool CheckIdPw(UserInfo& temp);
	bool CheckId(UserInfo& temp);
	bool AddIdPw(UserInfo& temp);
	UserInfo GetUserInfo(int index);
	int GetLastIndex(void);
};

SaveInformation::SaveInformation() : InputInfo() {}
SaveInformation::~SaveInformation() {}

void SaveInformation::Mangle(UserInfo temp) {
	int i=0;
	while (i < MAXLEN)
	{
		ValidIdPw[NextIndex].userID[i] = temp.userID[i] ^ hash[i];
		ValidIdPw[NextIndex].password[i] = temp.password[i] ^ hash[i];
		i++;
	}
#ifdef DEBUG
	cout << "The hashed password is " << ValidIdPw[0].password << endl;
	cout << "The hashed ID is " << ValidIdPw[0].userID << endl;
#endif // DEBUG
}

int SaveInformation::GetLastIndex(void) {
	return (NextIndex);
}

UserInfo SaveInformation::UnMangle(int index) {
	int i = 0;
	UserInfo temp;
	while (i < MAXLEN-1)
	{
		temp.userID[i] = ValidIdPw[index].userID[i] ^ hash[i];
		temp.password[i] = ValidIdPw[index].password[i] ^ hash[i];
		i++;
	}
#ifdef _DEBUG
	cout << "The unhashed password is " << temp.password << endl;
	cout << "The unhashed ID is " << temp.userID << endl;
#endif // DEBUG
	return temp;
}

int SaveInformation::ReadID(UserInfo &temp) {
	// This module checks the length of the input using string and converts the string to a char[].
	// In a production system there would be addtional checks for character types, numbers, capital 
	// and lower case letters and special symbols. If the criteria for a ID was not meet a retry would 
	// be requested. Only length is checked for this test.
	string check;
	int length;

	cout << "Enter User ID: ";
	cin >> check;
	cout << endl;
	length = check.length();

#ifdef DEBUG
	cout << "The length of ID is " << length;
	cout << endl;
#endif // DEBUG

	if (length <= MAXLEN-1) {
		check.copy(temp.userID, check.length() + 1, 0);
		//add a NULL after the last char to terminate the string, the copy method does not do that
		temp.userID[length] = NULL;

#ifdef DEBUG
		cout << "ID is " << temp.userID;
		cout << endl;
#endif // DEBUG

	}
	else {
		cout << endl;
		cout << "Invalid entry, must be less that 10 characters!";
		cout << endl;
	}
	// returns the length for more checking
	return length;
}

int SaveInformation::ReadPW(UserInfo &temp) {
	string check;
	int length;
	// the same functions as ReadID above for the password.
	cout << "Enter Your Password: ";
	cin >> check; 
	cout << endl;
	length = check.length();

#ifdef DEBUG
	cout << "The length of Password is " << length;
	cout << endl;
#endif // DEBUG

	if (length <= MAXLEN-1) {
		check.copy(temp.password, check.length() + 1);
		temp.password[length] = NULL;

#ifdef DEBUG
		cout << "Password is " << temp.password;
		cout << endl;
#endif // DEBUG

	}
	else {
		cout << endl;
		cout << "Invalid entry, must be less that 10 characters!";
		cout << endl;
	}
	return length;
}

bool SaveInformation::AddIdPw(UserInfo& temp) {
	bool result = true;
	UserInfo sample;

	//Does the ID already exist?
	for (int i = 0; i < NextIndex; i++) {
		sample = UnMangle(i);
		cout << "Loop count is" << i << endl;
		if (temp.userID == sample.userID) {
			cout << "This ID cannot be used.";
			result = false;
		}
		cout << endl;
		// Do not check if this password exists, that would be providing too much information.
		// Duplicate passwords are not necessarily bad.
	}
	if(result == true) {
		ValidIdPw[NextIndex] = temp;
#ifdef DEBUG
			cout << "ID " << NextIndex << " is " << ValidIdPw[NextIndex].userID << endl;
			cout << "Password " << NextIndex << " is " << ValidIdPw[NextIndex].password << endl;
			cout << endl;
#endif // DEBUG
		if (NextIndex < (MAXLEN * 2)) {
			Mangle(ValidIdPw[NextIndex++]);
		}
		else {
			cout << "Registry is full!" << endl;
		}
#ifdef DEBUG
			cout << "mangled ID " << (NextIndex -1) << " is " << ValidIdPw[NextIndex-1].userID << endl;
			cout << "mangled Password " << (NextIndex - 1) << " is " << ValidIdPw[NextIndex-1].password << endl;
			cout << endl;
#endif // DEBUG
	}

#ifdef DEBUG
	for (int i = 0; i < NextIndex; i++) {
		cout << "Savd ID " << i << " is " << ValidIdPw[i].userID << endl;
		cout << "Saved Password " << i << " is " << ValidIdPw[i].password << endl;
		cout << endl;
	}
#endif // DEBUG

	return result;
}
bool SaveInformation::CheckId(UserInfo &temp) {
	bool result = false;
	UserInfo sample;
	//Search the saved array for a matching ID and password. 
	for (int i = 0; i < NextIndex; i++) {
		sample = UnMangle(i);
		if (temp.userID == sample.userID)
			result = true;
	}
	return result;
}

bool SaveInformation::CheckIdPw(UserInfo &temp) {
	bool result = false;
	UserInfo sample;
	//Search the saved array for a matching ID and password. 
	for (int i = 0; i < NextIndex; i++) {
		sample = UnMangle(i);
		if (temp.userID == sample.userID)
			if (temp.password == sample.password)
				result = true;
	}
	return result;
}

UserInfo SaveInformation::GetUserInfo(int index) {
	return ValidIdPw[index];
}

string CheckYesNo(string input) {
	// Check and consolidare all reasonable responses for yes or no.
	string response = "Invalid";

	if (input == "yes" || input == "Yes" || input == "YES" || input == "y" | input == "Y") 
		response = "yes";
	else if (input == "no" || input == "No" || input == "NO" || input == "n" | input == "N") 
		response = "no";
	return response;
}

UserInfo WriteFile(UserInfo record[], int count) {
	static int index = 0;
	static const char* filename = "Auth.txt";
	static const UserInfo test[] = { "Dwayne", "Password1", "Arthur", "Password2","Edling", "Password3"};

	cout << test[0].password << test[0].userID << endl;
	cout << test[1].password << test[1].userID << endl;
	cout << test[2].password << test[2].userID << endl;

	// write a file
	cout << "write the file:" << count << endl;

	ofstream output(filename);
	if (output.is_open()) {
		while (index < count) {
			output << index << " " << test[index].userID << " " << test[index].password << endl;
			index++;
		}
		cout << "The file text is " << count << endl;
		output.close();
	}
	else cout << "Unable to open myfile text...";
	while(index < count) {
		output << ++index << " " << record[index].password << " " << record[index].userID << endl;
	}
	
	output.close();

	

	// delete file
	//cout << "delete file." << endl;
	//remove(filename);
	return(*test);
 }

union chrstr
{
public:
	char chr[MAXLEN];
	string str;
};

void ReadFile(int count) {
	static int offset, index = 0;
	static const char* filename = "Auth.txt";
	static const char* textstring = "This is the test file";
	UserInfo test[MAXLEN*2];
	
	//UserInfo* record;
	chrstr temp;

	// read a file
	string buf = "test";
	char saved[MAXLEN];
	cout << "read the file:" << endl;
	//ifstream infile(filename);
	//ofstream output(filename);
	ifstream input(filename);
	if (input.is_open()) {
		//input.getline(buf, sizeof(buf));
		input >> buf;
		if (buf == "0") {
			offset = 0;
		} else cout << "NEED CONVERSION";
		cout << "This is buf1 " << buf << endl;
		input >> buf;
		*saved = (void*)&buf;
		*test[offset].userID = (char*)buf.c_str();
		cout << "This is buf2 " << buf << endl;
		input >> buf;
		test[offset].userID = reinterpret_cast<char*> buf;
		cout << "This is buf3 " << buf << endl;
		input >> buf;
		if (buf == "1") {
			offset = 1;
		} else cout << "NEED CONVERSION";
		cout << "This is buf1 " << buf << endl;
		input >> buf;
		test[offset].userID = (char*)buf.c_str();
		cout << "This is buf2 " << buf << endl;
		input >> buf;
		test[offset].userID = (char*)buf.c_str();
		cout << "This is buf3 " << buf << endl;
		input >> buf;
		if (buf == "2") {
			offset = 2;
		} else cout << "NEED CONVERSION";
		cout << "This is buf1 " << buf << endl;
		input >> buf;
		test[offset].userID = (char*)buf.c_str();
		cout << "This is buf2 " << buf << endl;
		input >> buf;
		test[offset].userID = (char*)buf.c_str();
		cout << "This is buf3 " << buf << endl;
		input.close();
	} else cout << "Unable to open input file text...";
	/*while (index=0 < count){
		cout << count << endl;
		offset = index * MAXLEN * 2;
		cout << offset << endl;
		for (int x = 0; x < (MAXLEN * 2); x++){
			cout << buf[offset + x];
		}
		cout << endl;
		index++;
	}*/

	// delete file
	//cout << "delete file." << endl;
	//remove(filename);
	//return record;
}



int main()
{
	// UserInfo saved = {"Dwayne", "CPlus2019"};
	UserInfo saved, check, temp; 
	//UserInfo test[MAXLEN*2];
	string input = "", line = "test";

	int attempt = 3, index, count;

	SaveInformation Authenticate;
	//saved = Authenticate.GetUserInfo(0);
	//Authenticate.Mangle(saved);
	//Authenticate.UnMangle(0);
	/*char buf[MAXLEN];
	input = "Dwayne, CPlus2019\n";
	//buf = input;
	cout << "Test it is " << line << endl;
	ofstream outputfile("Auth.txt");
	//outputfile.open("Auth.txt");
	if (outputfile.is_open()) {
		outputfile << input;
		cout << "The file text is " << input << endl;
		outputfile.close();
	} else cout << "Unable to open myfile text...";
	ifstream inputfile("Auth.txt");
	//inputfile.open("Auth.txt");
	if (inputfile.is_open()) {
		cout << "This is from Auth.txt before " << line << endl;
		inputfile >> line;
		//inputfile >> saved;
		cout << "This is from Auth.txt after " << line << endl;
		inputfile.close();
		
	} else cout << "Unable to open myifile text...";*/

	//WriteFile(test, 3);
	ReadFile(3);

	cout << "Do you have an account? (answer yes or no) ";
	cin >> input;
	cout << endl;
	if(CheckYesNo(input) == "yes") {
		// An account exist in the system.
		// Read the index file.
		index = 0;
		ofstream indexout("index.bin");
		ifstream myindex ("index.bin");
		if (myindex.is_open()) {
			myindex >> index;
			cout << "The file index is " << index << endl;
		} else cout << "Unable to open index file" << endl;

		//int zero = (char) "0";
		//int maxlen = (char)("0" + (MAXLEN*2));
		//cout << "zero is" << zero << endl;
		//cout << "maxlen is" << maxlen << endl;
		if (index > 0) {
			for (int i = index; i >= 0; i--) {
				if (myindex.is_open()) {
					myindex >> count;
					cout << "The file count is " << count << endl;
				}
				else cout << "Unable to open data file";
			}
		}
		for(int i = index; i >= 0; i--) {
			//myfile.open("Autentication.txt");
			//if (myfile.is_open()) {
			//	myfile >> line;
			//	cout << "The file index is " << line;
			//} else cout << "Unable to open data file";


		}
		cout << "Start While" << endl;
		while (attempt != 0) {
			cout << "step 1" << endl;
			if (Authenticate.ReadID(check) > (MAXLEN - 1)) {
				cout << "User ID is illegal!" << endl;
				break;
			}
			cout << "step 2" << endl;
			if (Authenticate.ReadPW(check) > (MAXLEN - 1)) {
				cout << "Password is illegal!" << endl;
				break;
			}
			cout << "step 3 Index is " << Authenticate.GetLastIndex() << endl;
			for (int i = 0; i <= Authenticate.GetLastIndex(); i++) {
				saved = Authenticate.GetUserInfo(i);
				cout << "Saved ID is " << saved.userID << endl;
				cout << "Check ID is " << check.userID << endl;
				cout << endl;

				if (strcmp(saved.userID, check.userID) == 0 && strcmp(saved.password, check.password) == 0) {
					cout << "Login Succeeded!" << endl;
					break;
				}
			}
			cout << "Invalid User ID or Password, please try again!" << endl;
			attempt--;
			cout << endl;
			if (attempt)
				cout << "You have " << attempt << " more chances..." << endl;
			else
				cout << "Login Failed!" << endl;
			cout << endl;
		}
	}
	else {
		// The user does not have an account
		if (CheckYesNo(input) == "no") {
			cout << "Do you want to create an account? (answer yes or no) ";
			cin >> input;
			cout << endl;
			if (CheckYesNo(input) == "no")
				// The user does not want an account
				cout << "Thanks for visting our site!";
			else
				if (CheckYesNo(input) == "yes") {
					// We need to create a new user account
					// Check length first with ReadID and ReadPW, we can only handle 9 characters
					if (((Authenticate.ReadID(temp)) < MAXLEN) && ((Authenticate.ReadPW(temp))) < MAXLEN) {
						if (Authenticate.AddIdPw(temp) == true) {
							
							//if (myindex.is_open()) {
							//	myindex << Authenticate.GetLastIndex();
							//	cout << "The file index is " << index;
							//else cout << "Unable to open index file";
							
							//if (myfile.is_open()) {
							//	myfile << saved.userID;
							//	myfile << saved.password;
							//	cout << "The file index is " << line;
							//} else cout << "Unable to open data file";

							// the ID does not already exist so we can create a new entry
							cout << "Your account has been created." << endl;
							cout << "Restart the program to log in." << endl;
							cout << endl;
						}
						else
							// This ID already exist
							cout << "This ID cannot be used!";
					}
				}
				else {
					cout << "Invalid response, thanks for visting our site!";
				}
		}
		else
			cout << "Invalid response, thanks for visting our site!";
	}
	return 0;
}
