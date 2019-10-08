
#include <iostream>
#include <string>
#include <iomanip>
#include <fstream>

using namespace std;

//#define DEBUG
#define MAXLEN 10	//the 10th character is a NULL, max length is 9
#define MANGLEN 4	// How many characters to mangle

enum RECTYPE { INDEX, ID, PW };

struct UserInfo {
	char userID[MAXLEN];
	char password[MAXLEN];
};


class SaveInformation {
	char hash[MAXLEN] = {0xf,0,1,0,0,0,0,0,0};
	UserInfo InputInfo = { "", "" };
	UserInfo ValidIdPw[MAXLEN * 2]; 

	bool CheckIdPw(UserInfo& temp);
	int NextIndex = 0;						
	void Mangle(UserInfo temp);
	UserInfo* GetAuthRecord(void);
	void PutAuthRecord(UserInfo*);
	bool CopyBufftoStruct(UserInfo*, string, int, RECTYPE);

public:
	SaveInformation(); //default
	~SaveInformation();//destructor
	UserInfo UnMangle(int index);
	int ReadID(UserInfo &temp);
	int ReadPW(UserInfo &temp);
	bool AddIdPw(UserInfo& temp);
	UserInfo GetUserInfo(int index);
	int GetLastIndex(void);
	void ReadFile(int count);
	void WriteFile(UserInfo record[], int count);
};

SaveInformation::SaveInformation() : InputInfo() {}
SaveInformation::~SaveInformation() {}

// MANGLE: This method mangles information before the file/structure
// element is saved. In production this would be an 
// encryption call
void SaveInformation::Mangle(UserInfo temp) {
	int i = 0, CurrIndex = NextIndex - 1;

	while (i < MAXLEN and NextIndex != 0)
	{
		ValidIdPw[CurrIndex].userID[i] = temp.userID[i] ^ hash[i];
		ValidIdPw[CurrIndex].password[i] = temp.password[i] ^ hash[i];
		i++;
	}
#ifdef DEBUG
	cout << "NextIndex " << NextIndex << endl;
	cout << "temp id and pw " << temp.userID << " " << temp.password << endl;
	cout << "ValidIdPw " << ValidIdPw[CurrIndex].userID << " " << ValidIdPw[CurrIndex].password << endl;
	cout << "The hashed passwordM is " << ValidIdPw[0].password << endl;
	cout << "The hashed IDM is " << ValidIdPw[0].userID << endl;
#endif // DEBUG
}

int SaveInformation::GetLastIndex(void) {
#ifdef DEBUG
	cout << "Current Index is " << NextIndex << endl;
#endif // DEBUG
	return (NextIndex);
}

// UNMANGLE: This method recovers the mangled information
// in saved file/structure. In production this would be an 
// decryption call.
UserInfo SaveInformation::UnMangle(int index) {
	int i = 0;
	UserInfo temp;

	while (i < MAXLEN)
	{
		temp.userID[i] = ValidIdPw[index].userID[i] ^ hash[i];
		temp.password[i] =  ValidIdPw[index].password[i] ^ hash[i];
		i++;
	}
	return temp;
}

// ReadID: This module checks the length of the input using string and converts the string to a char[].
int SaveInformation::ReadID(UserInfo &temp) {
	
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

// ReadPW: This module checks the length of the input using string and converts the string to a char[].
// In a production system there would be addtional checks for character types like numbers, capital 
// and lowercase letters and special symbols. If the criteria for a PW strength was not meet (something 
// like must include 3 of these elements) a retry would be requested. Only length is checked for 
// this test.
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
// AddIdPw: This module adds the ID and Password to the structure/file
bool SaveInformation::AddIdPw(UserInfo& temp) {
	bool result = true;
	UserInfo sample;

	//Does the ID already exist?

	// Unmangle the IDs to check them
	for (int i = 0; i < NextIndex; i++) {
		sample = UnMangle(i);

		// Look fo any matchig IDs
		if (temp.userID == sample.userID) {
			cout << "This ID cannot be used.";
			result = false;
		}
		cout << endl;
		// Do not check if this password exists, that would be providing too much information.
		// Duplicate passwords are not necessarily bad.
	}
	if(result == true) {
		// Check if our file is full, I artifically set a low limit.
			if (NextIndex < (MAXLEN * 2)) {
				// Save the ID and password to structure/file
				ValidIdPw[NextIndex] = temp;
				// This is the only place were NextIndex is incremented
				Mangle(ValidIdPw[NextIndex++]);
				int CurrIndex = NextIndex - 1;
			}
			else {
				cout << "Registry is full!" << endl;
			}
	}

	// Let caller know if this succeeded.
	return result;
}

UserInfo* SaveInformation::GetAuthRecord(void) {
	return &ValidIdPw[0];
}

void SaveInformation::PutAuthRecord(UserInfo*) {

}

//CheckID: Checks the ID and PW for a macth in the structure/file.
bool SaveInformation::CheckIdPw(UserInfo &temp) {
	bool result = false;
	UserInfo sample;
	//Search the saved array for a matching ID and password. 
	
	if (NextIndex != 0) {//There is nothing to check if NextIndex == 0.
		for (int i = 0; i < NextIndex; i++) {
			cout << "Unmangle sample!" << endl;
			sample = UnMangle(i);
			cout << "UnMangled Id sample1 is " << sample.userID << endl;
			cout << "UnMangled Id temp1 is " << temp.userID << endl;
			if (temp.userID == sample.userID)
				if (temp.password == sample.password)
					result = true;
		}
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

void SaveInformation::WriteFile(UserInfo record[], int count) {
	static int index = 0;
	static const char* filename = "Auth.txt";

	// write a file

	ofstream output(filename);
	if (output.is_open()) {
		while (index < count) {
			// format for each entry: index <space> ID <space> password <EOL> 
			output << index << " " << ValidIdPw[index].userID << " " << ValidIdPw[index].password << endl;
			index++;
		}
		output.close();
	}
	else cout << "Unable to open myfile text...";
	while(index < count) {
		output << ++index << " " << record[index].password << " " << record[index].userID << endl;
	}
	
	output.close();
}



// Copies a striing value into the authorization structure.
bool SaveInformation::CopyBufftoStruct(UserInfo *test, string buf, int offset, RECTYPE type) {
	
	//UserInfo* record used for copy;
	char temp[MAXLEN];

#ifdef DEBUG
	cout << "This is a type " << type << " buffer value is " << buf << " offset is " << offset << endl;
#endif // DEBUG

	// Copy the string to an array. 
	std::strcpy(temp, buf.c_str());

	// Copy the array to the struct/record
	for (int i = 0; i < MAXLEN; i++) {
		if (type == ID) {
			test[offset].userID[i] = temp[i];
		}
		else if (type == PW) {
			test[offset].password[i] = temp[i];
		}
		else {
			cout << "Copy type did not match!" << endl;
			return false;
		}
	}
#ifdef DEBUG
	if (type == ID) {
		cout << "The ID put in strut is " << test[offset].userID << endl;
	}
	else {
		cout << "The PW put in strut is " << test[offset].password << endl;
	}
#endif // DEBUG
	return true;
}

// ReadFile: Reads a file in and moves to to a temporary structure. For use by other methods
void SaveInformation::ReadFile(int count) {
	static int offset = 0, index = 0;
	static const char* filename = "Auth.txt";
	static const char* textstring = "This is the test file";

	// read a file
	string buf = "test";
	//cout << "read the file:" << endl;
	ifstream input(filename);
	if (input.is_open()) {
		while (!input.eof()) {
			// This builds the private UserInfo ValidIdPw struct.
			input >> buf; //buf 1 index
			if (buf == "" || input.eof()) break; // Did not read in a buffer.
			offset = stoi(buf, nullptr);
			input >> buf; //buf 2 ID
			if (input.eof()) break; // Did not read in a buffer. 
			CopyBufftoStruct(ValidIdPw, buf, offset, ID);
			input >> buf; //buf 3 password
			if (input.eof()) break; // Did not read in a buffer.
			CopyBufftoStruct(ValidIdPw, buf, offset, PW);
			buf = "";
		}
		// Set the NextIndex pointer
		NextIndex = offset + 1;
		//cout << "Out of while loop." << endl;
	} else cout << "Initial state no read file exist" << endl;

	input.close();
}



int main()
{
	// UserInfo saved = {"Dwayne", "CPlus2019"};
	UserInfo saved, check, temp; 
	UserInfo test[MAXLEN*2];
	string input = "", line = "test";
	bool login = false;

	int attempt = 3 /* index, count*/ ;
	SaveInformation Authenticate;
	// Read the existing file. YOU NEED TO FIX THE 3 BELOW.
	Authenticate.ReadFile(3);
	cout << endl;
	cout << "Do you have an account? (answer yes or no) ";
	cin >> input;
	cout << endl;
	if(CheckYesNo(input) == "yes") {
		// An account exist in the system.
		while (attempt != 0) {
			// Give the user 3 tries to log in
			// Is the ID is too long just exit
			if (Authenticate.ReadID(check) > (MAXLEN - 1)) {
				cout << "User ID is illegal!" << endl;
				break;
			}
			// If the PW is too long just exit.
			if (Authenticate.ReadPW(check) > (MAXLEN - 1)) {
				cout << "Password is illegal!" << endl;
				break;
			}
			for (int i = 0; i <= (Authenticate.GetLastIndex()-1); i++) {
				//saved = Authenticate.GetUserInfo(i);
				saved = Authenticate.UnMangle(i);

				if (std::strcmp(saved.userID, check.userID) == 0 && std::strcmp(saved.password, check.password) == 0) {
					login = true;
					attempt = 0;
					i = Authenticate.GetLastIndex() + 1;
					cout << "Login Succeeded!" << endl;
					break;
				}
			}
			if (login == false) {
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
				// The user wants an account, ask for a user ID and a password.
				if (CheckYesNo(input) == "yes") {
					// We need to create a new user account
					// Check length first with ReadID and ReadPW, we can only handle 9 characters
					if (((Authenticate.ReadID(temp)) < MAXLEN) && ((Authenticate.ReadPW(temp))) < MAXLEN) {
						// Add the autentication information to our structure.
						if (Authenticate.AddIdPw(temp) == true) {
							// Save this updated information to our file.
							Authenticate.WriteFile(test, Authenticate.GetLastIndex());
							cout << "Account has been created" << endl;
							cout << "Restart the program to log in." << endl;
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
