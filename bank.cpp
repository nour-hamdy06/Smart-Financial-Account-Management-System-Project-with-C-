// Smart Financial Account Management System - SHORT version
// Files: accounts.txt (id hash balance failed lockedUntil name), transactions.txt (readable log)
// The PIN is never saved. We save its SHA-256 hash (64 characters).

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <ctime>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#ifdef _WIN32
  #include <conio.h>
#else
  #include <termios.h>
  #include <unistd.h>
#endif
using namespace std;

struct Account {
    int id;
    string hash;                 // SHA-256 of (id + PIN)
    double balance;
    int failed = 0;              // wrong PINs in a row
    long long lockedUntil = 0;   // 0 = not locked
    string name;
};
vector<Account> accounts;        // all accounts in memory
vector<string> logLines;         // new log lines, written at Save

// ---------------- SHA-256: turns any text into a 64-character fingerprint ----------------
uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

string sha256(string text) {
    uint32_t k[64], h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    int primes = 0;                                   // k[] = cube roots of the first 64 primes
    for (int n = 2; primes < 64; n++) {
        bool isPrime = true;
        for (int d = 2; d * d <= n; d++) if (n % d == 0) isPrime = false;
        if (!isPrime) continue;
        double root = 1; for (int i = 0; i < 60; i++) root = (2 * root + n / (root * root)) / 3;
        k[primes++] = (uint32_t)((root - (uint32_t)root) * 4294967296.0);
    }
    string msg = text + (char)0x80;                   // 1) padding up to a multiple of 64 bytes
    while (msg.size() % 64 != 56) msg += (char)0;
    for (int i = 7; i >= 0; i--) msg += (char)((uint64_t)text.size() * 8 >> (i * 8));
    for (size_t pos = 0; pos < msg.size(); pos += 64) {   // 2) mix each 64-byte block
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint8_t)msg[pos+i*4] << 24) | ((uint8_t)msg[pos+i*4+1] << 16) | ((uint8_t)msg[pos+i*4+2] << 8) | (uint8_t)msg[pos+i*4+3];
        for (int i = 16; i < 64; i++)
            w[i] = w[i-16] + (rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3)) + w[i-7]
                 + (rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10));
        uint32_t v[8]; for (int i = 0; i < 8; i++) v[i] = h[i];
        for (int i = 0; i < 64; i++) {                // 64 rounds of mixing
            uint32_t t1 = v[7] + (rotr(v[4],6) ^ rotr(v[4],11) ^ rotr(v[4],25)) + ((v[4] & v[5]) ^ (~v[4] & v[6])) + k[i] + w[i];
            uint32_t t2 = (rotr(v[0],2) ^ rotr(v[0],13) ^ rotr(v[0],22)) + ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));
            for (int j = 7; j > 0; j--) v[j] = v[j-1];
            v[4] += t1; v[0] = t1 + t2;
        }
        for (int i = 0; i < 8; i++) h[i] += v[i];
    }
    string out; char part[9];                         // 3) write the 8 numbers as 64 hex characters
    for (int i = 0; i < 8; i++) { snprintf(part, sizeof part, "%08x", h[i]); out += part; }
    return out;
}

// The account number is mixed in, so two accounts with the same PIN get different hashes
string hashPin(string pin, int id) { return sha256(to_string(id) + pin); }

// ---------------- Input helpers ----------------
string readText(string message) {
    string s; cout << message; getline(cin, s);
    if (!cin) exit(0);
    return s;
}

string readPin(string message) {                      // typed PIN is hidden
    cout << message << flush;
    string pin;
#ifdef _WIN32
    char c;
    while ((c = _getch()) != '\r') {
        if (c == '\b' && !pin.empty()) { pin.pop_back(); cout << "\b \b"; }
        else if (c >= '0' && c <= '9' && pin.size() < 8) { pin += c; cout << '*'; }
    }
    cout << "\n";
#else
    termios old; tcgetattr(STDIN_FILENO, &old);
    termios hidden = old; hidden.c_lflag &= ~ECHO; tcsetattr(STDIN_FILENO, TCSANOW, &hidden);
    getline(cin, pin);
    tcsetattr(STDIN_FILENO, TCSANOW, &old); cout << "\n";
    if (!cin) exit(0);
#endif
    return pin;
}

bool isNumber(string s) {
    if (s.empty() || s.size() > 9) return false;
    for (char c : s) if (c < '0' || c > '9') return false;
    return true;
}

double readAmount(string message, bool allowZero = false) {   // -1 = invalid
    string s = readText(message);
    try {
        size_t used; double a = stod(s, &used);
        if (used == s.size() && a <= 50000 && (a > 0 || (a == 0 && allowZero))) return a;
    } catch (...) {}
    cout << "Invalid amount (0 - 50000).\n";
    return -1;
}

int findAccount(string idText) {                      // position, or -1
    if (!isNumber(idText)) return -1;
    for (int i = 0; i < (int)accounts.size(); i++)
        if (accounts[i].id == stoi(idText)) return i;
    return -1;
}

// ---------------- Files ----------------
void loadAccounts() {                                 // READ accounts.txt
    ifstream file("accounts.txt");
    Account a;
    while (file >> a.id >> a.hash >> a.balance >> a.failed >> a.lockedUntil) {
        getline(file, a.name);
        a.name.erase(0, 1);                           // remove the space before the name
        accounts.push_back(a);
    }
}

void saveToFile() {
    ofstream file("accounts.txt");                    // OVERWRITE accounts.txt
    for (Account a : accounts)
        file << a.id << " " << a.hash << " " << a.balance << " " << a.failed << " " << a.lockedUntil << " " << a.name << "\n";
    ofstream log("transactions.txt", ios::app);       // APPEND to transactions.txt
    for (string line : logLines) log << line << "\n";
    logLines.clear();
}

void addLog(int id, string type, double amount, double balanceAfter) {
    char when[30], line[200];
    time_t now = time(0);
    strftime(when, sizeof when, "%Y-%m-%d %H:%M:%S", localtime(&now));
    snprintf(line, sizeof line, "%s | Account %d | %s | %.2f | Balance after: %.2f", when, id, type.c_str(), amount, balanceAfter);
    logLines.push_back(line);
}

// ---------------- <Source Valid?> : account number + PIN, with 5-minute lock ----------------
int authenticate(string pinMessage = "PIN: ") {
    int pos = findAccount(readText("Account number: "));
    string pin = readPin(pinMessage);
    if (pos == -1) { cout << "Invalid account number or PIN.\n"; return -1; }

    Account& acc = accounts[pos];
    long long now = time(0);
    if (acc.lockedUntil != 0 && acc.lockedUntil <= now) { acc.lockedUntil = 0; acc.failed = 0; }   // lock time is over
    if (acc.lockedUntil > now) {
        cout << "Account locked. Try again in " << (acc.lockedUntil - now) / 60 << " min " << (acc.lockedUntil - now) % 60 << " sec.\n";
        return -1;
    }
    if (hashPin(pin, acc.id) != acc.hash) {           // wrong PIN
        addLog(acc.id, "WRONG_PIN", 0, acc.balance);
        if (++acc.failed >= 3) {
            acc.lockedUntil = now + 5 * 60;
            addLog(acc.id, "ACCOUNT_LOCKED", 0, acc.balance);
            cout << "3 wrong PINs. Account locked for 5 minutes.\n";
        } else cout << "Invalid account number or PIN.\n";
        saveToFile();                                 // save now, so closing the program does not reset the counter
        return -1;
    }
    acc.failed = 0;
    return pos;
}

// ---------------- Operations (true = success -> goes to <More Ops?>) ----------------
bool createAccount() {
    string name = readText("Name: "), pin = readPin("PIN (6 digits): "), pin2 = readPin("Confirm PIN: ");
    if (name.empty() || name.size() > 30 || pin.size() != 6 || !isNumber(pin)) { cout << "Invalid name or PIN (6 digits).\n"; return false; }
    if (pin != pin2) { cout << "PINs do not match.\n"; return false; }
    double opening = readAmount("Opening balance (0 - 50000): ", true);
    if (opening < 0) return false;

    Account a;
    a.id = accounts.empty() ? 1001 : accounts.back().id + 1;
    a.hash = hashPin(pin, a.id);
    a.balance = opening;
    a.name = name;
    accounts.push_back(a);
    addLog(a.id, "CREATE", opening, opening);
    cout << "Account created. Your account number: " << a.id << "\n";
    return true;
}

bool depositMoney() {
    int pos = findAccount(readText("Account number: "));
    if (pos == -1) { cout << "Account not found.\n"; return false; }
    double amount = readAmount("Amount to deposit: ");
    if (amount < 0) return false;
    accounts[pos].balance += amount;                  // [Update Balance]
    addLog(accounts[pos].id, "DEPOSIT", amount, accounts[pos].balance);
    cout << "New balance: " << accounts[pos].balance << "\n";
    return true;
}

bool withdrawMoney() {
    int pos = authenticate();
    if (pos == -1) return false;
    double amount = readAmount("Amount to withdraw: ");
    if (amount < 0) return false;
    if (amount > accounts[pos].balance) { cout << "Not enough balance.\n"; return false; }   // <Enough Balance?>
    accounts[pos].balance -= amount;                  // [Update Balance]
    addLog(accounts[pos].id, "WITHDRAW", amount, accounts[pos].balance);
    cout << "New balance: " << accounts[pos].balance << "\n";
    return true;
}

bool transferMoney() {
    int from = authenticate("Your PIN: ");
    if (from == -1) return false;
    int to = findAccount(readText("Send to account number: "));
    if (to == -1 || to == from) { cout << "Invalid destination account.\n"; return false; }
    double amount = readAmount("Amount to send: ");
    if (amount < 0) return false;
    if (amount > accounts[from].balance) { cout << "Not enough balance.\n"; return false; }
    accounts[from].balance -= amount;                 // [Update Balance] on both accounts
    accounts[to].balance += amount;
    addLog(accounts[from].id, "TRANSFER_OUT to " + to_string(accounts[to].id), amount, accounts[from].balance);
    addLog(accounts[to].id, "TRANSFER_IN from " + to_string(accounts[from].id), amount, accounts[to].balance);
    cout << "Sent " << amount << ". Your new balance: " << accounts[from].balance << "\n";
    return true;
}

bool showBalance() {
    int pos = authenticate();
    if (pos == -1) return false;
    cout << accounts[pos].name << " balance: " << accounts[pos].balance << "\n";
    return true;
}

bool showTransactions() {                             // READ the file and FILTER this account's lines
    int pos = authenticate();
    if (pos == -1) return false;
    string key = "| Account " + to_string(accounts[pos].id) + " |";
    string line;
    ifstream file("transactions.txt");
    while (getline(file, line)) if (line.find(key) != string::npos) cout << line << "\n";
    for (string l : logLines) if (l.find(key) != string::npos) cout << l << "\n";   // this session's new lines
    return true;
}

bool changePin() {
    int pos = authenticate("Current PIN: ");
    if (pos == -1) return false;
    string p1 = readPin("New PIN (6 digits): "), p2 = readPin("Confirm new PIN: ");
    if (p1.size() != 6 || !isNumber(p1) || p1 != p2) { cout << "PIN must be 6 digits and match.\n"; return false; }
    accounts[pos].hash = hashPin(p1, accounts[pos].id);
    addLog(accounts[pos].id, "PIN_CHANGED", 0, accounts[pos].balance);
    cout << "PIN changed.\n";
    return true;
}

// ---------------- main = the flowchart ----------------
int main() {
    loadAccounts();                                   // Load Accounts from File
    while (true) {
        cout << "\n1) Create account  2) Deposit  3) Withdraw  4) Transfer\n"
             << "5) Balance  6) Transaction records  7) Change PIN  8) Exit\n";   // Display Menu
        string choice = readText("Choose: ");         // Read Choice
        if (choice == "8") break;                     // Exit -> Save to File
        
        bool done = false;
        if      (choice == "1") done = createAccount();
        else if (choice == "2") done = depositMoney();
        else if (choice == "3") done = withdrawMoney();
        else if (choice == "4") done = transferMoney();
        else if (choice == "5") done = showBalance();
        else if (choice == "6") done = showTransactions();
        else if (choice == "7") done = changePin();
        else cout << "Invalid choice.\n";

        if (!done) continue;                          // "No" branch -> back to the menu
        string more = readText("More operations? (y/n): ");   // More Ops?
        if (more != "y" && more != "Y") break;
    }
    saveToFile();                                     // Save to File
    cout << "Data saved. Goodbye!\n";
    return 0;
}
