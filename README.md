Main Features of the Project
This project implements a secure and modular multi-factor authentication system using C++. The system offers a combination of biometric (fingerprint), password-based, and OTP (One-Time Password) authentication to validate user identity. It includes a user registration feature that collects and validates user details including username, email, password, and fingerprint. The login process is designed with fallback mechanisms that attempt fingerprint authentication first, followed by password, and finally OTP-based verification. If a user forgets their password, the system provides a password reset functionality using a secure email token. Data is stored in CSV and text files using the FileManager class, and sensitive data such as passwords and tokens are encrypted using the Windows CryptoAPI. The system integrates external APIs such as libcurl for Gmail SMTP email delivery and the Windows Biometric Framework for fingerprint recognition.

Object-Oriented Programming Principles Employed
1. Encapsulation
•	Achieved using the FileManager class.
•	All file-related operations such as user registration (addUser()), password verification (verifyPassword()), token handling, and fingerprint storage are handled internally.
•	The internal implementation is hidden from other classes, ensuring separation of concerns.
2. Inheritance
•	Implemented through the AuthStrategy base class.
•	Derived classes include PasswordAuth, OTPAuth, and FingerPrintAuth.
•	These subclasses inherit from AuthStrategy and provide their own implementation of the authenticate() function.
3. Polymorphism
•	The authenticate() method in AuthStrategy is overridden in all child classes.
•	This allows dynamic selection of the authentication method (e.g., password, fingerprint, OTP) at runtime.
•	UserRegistration uses a pointer to AuthStrategy to handle authentication generically.
4. Abstraction
•	The user is not exposed to the internal logic of encryption, fingerprint scanning, or email sending.
•	High-level interfaces (e.g., authenticate(), loginWithFallback()) allow easy interaction with complex subsystems like WinBio API and libcurl.
•	Strategy design pattern is used to hide internal algorithmic complexity behind a common interface.
5. Modularity
•	Each feature is encapsulated in its own class:
o	UserRegistration for user interaction
o	AuthStrategy and its subclasses for authentication
o	FileManager for file handling
•	This design supports easier debugging, testing, and future enhancements.
Step-by-Step Solution
The authentication system is structured around several key modules and follows a sequential flow starting from user registration to fallback-based login and password reset. Each module is encapsulated into its respective class and communicates through clean interfaces. Below is a detailed walkthrough of how each part of the system operates:
1. User Registration:
The registration begins in the registerUser() function of the UserRegistration class. The user is prompted to enter a username, which is validated using the isValidUsername() function. This check ensures the username is alphanumeric, allows underscores or dashes, and does not exceed 30 characters. Next, the email is validated through the isValidEmail() function to ensure proper format, structure, and domain. The password entered by the user is then validated using isStrongPassword() to confirm it is between 8 to 16 characters long and contains at least one uppercase letter, one lowercase letter, and one numeric digit.
2. Fingerprint Capture and Identity Mapping:
After successful validation, the system invokes the FingerPrintAuth::captureAndIdentify() function. Internally, this uses the Windows Biometric API function WinBioIdentify() to acquire a biometric identity. The identityToSidString() function then converts the captured biometric SID to a string format, which is saved in the user file. This step ensures a unique biometric identity is tied to each user.
3. Password Hashing and User Data Storage:
The validated password is securely hashed using the hashPassword() function, which uses the Windows CryptoAPI (CryptAcquireContext, CryptCreateHash, and CryptHashData). The complete user data (username, email, hashed password, fingerprint SID, and timestamp) is then stored in a CSV file using the FileManager::addUser() method.
4. Login Flow with Fallback Authentication:
The login logic is managed by the loginWithFallback() function. The system first checks if the email is registered using FileManager::isEmailRegistered() and ensures the user has not exceeded login attempts with checkRateLimit().
•	Step 1 – Fingerprint Authentication: The FingerPrintAuth::authenticate() method is triggered first. It compares the newly scanned fingerprint SID with the stored SID fetched from FileManager::getFingerprintData(). If it matches, access is granted.
•	Step 2 – Password Authentication: If the fingerprint fails, the system prompts for a password. PasswordAuth::authenticate() hashes the input password with hashPassword() and checks it against the stored hash using verifyPassword(). If matched, login is successful.
•	Step 3 – OTP Authentication: If both prior methods fail, the OTPAuth::authenticate() function generates a 6-digit OTP using generateOTP() and emails it through sendOTPEmail(), which uses libcurl (curl_easy_setopt) for Gmail SMTP. The OTP is stored with a timestamp in memory. On user input, the OTP is validated and checked for expiration using difftime().
5. Password Reset with Token Verification:
If a user forgets their password, they can initiate a reset via the resetPasswordWithToken() function. This calls PasswordAuth::initiatePasswordReset(), which generates a random token using generateRandomToken() and stores it in a file via addResetToken(). The token is encrypted using encryptToken() (which uses AES-256 via CryptoAPI functions like CryptDeriveKey) and sent to the user's email using sendResetEmail() through libcurl.
Once the user receives the token, they enter it for verification. The system then decrypts the stored token using decryptToken() and matches it with the input. Upon success, the user can enter a new password, which is validated and updated using updatePassword().
6. Rate Limiting:
To prevent brute-force attacks, login attempts are tracked in attempts.txt using the checkRateLimit() function. This function stores the timestamp of each attempt and denies access if more than five attempts are made within one hour.
7. Overall Modularity and Class Usage:
Each authentication type is implemented in its own class (PasswordAuth, OTPAuth, FingerPrintAuth), inheriting from the common base class AuthStrategy. The authenticate() function is overridden in each class to implement method-specific logic. The UserRegistration class orchestrates user input and calls the appropriate strategies based on the fallback order. The FileManager class centralizes all file handling logic, maintaining separation of concerns.

Design patterns used :
Strategy Pattern
The system implements the Strategy Pattern through the use of the AuthStrategy abstract base class, which defines a common interface with the authenticate() method. The three derived classes—PasswordAuth, OTPAuth, and FingerPrintAuth—each provide their own implementation of this method. This allows the authentication mechanism to vary independently of the UserRegistration logic that uses it. By selecting the appropriate strategy at runtime, the system achieves flexible authentication without altering the structure of the user interface or main control flow. This pattern promotes loose coupling and enhances code scalability.

Factory Pattern
The Factory Pattern is applied via the AuthFactory class, which encapsulates the logic for object creation. The method createAuthStrategy(type) accepts a string argument (such as "password", "otp", or "fingerprint") and returns a corresponding object of type AuthStrategy. This pattern abstracts the instantiation process and separates it from the client code that uses the objects. It helps in maintaining clean architecture, reducing direct dependencies, and simplifying the addition of new authentication strategies in the future without modifying existing logic.
Templates
Although C++ templates are not directly used in this project, the design reflects template-like flexibility through polymorphism and reusable components. For example, the AuthStrategy base class and its subclasses provide a template-like structure for defining different types of authentication without duplicating code. If the project were to be extended, templates could be introduced to generalize input validation or file handling functions, allowing them to operate on various data types. This demonstrates the project’s modularity and readiness for generic programming practices.

Limitations of the Adopted Approach
1. Works Only on Windows (Needs Flexibility)
Right now, the project only runs on Windows because it uses tools that only work there. To make it usable on Mac or Linux, we can switch to tools that work everywhere, like OpenSSL for encryption or FPrint for fingerprint scanning.
2. Email Passwords Are Exposed (Needs Security)
We typed the Gmail username and password directly in the code, which is risky. A safer way is to hide these details using system settings or secret storage tools like Azure Key Vault.
3. Plain Text File Storage (Needs Better Saving Method)
User information is saved in simple text files. This can be slow or messy for big projects. Using a small database like SQLite or online services like Firebase would make it faster and easier to manage.
4. Only Text-Based Interface (Needs a Better Look)
The system runs in the black command box (console), which can be hard for non-tech users. We can improve it by making a nice window-based version with buttons and forms using tools like Qt or WxWidgets.

Task Distribution Among Team Members
The development of this project was a team effort divided among three members.
 Sana Zehra was responsible for implementing all input validations, including email format, username rules, and password strength checks (isValidEmail(), isValidUsername(), and isStrongPassword() functions). Moreover, she designed and implemented the UserRegistration class which seamlessly resgisters a new user.
 Aleeza Mujahid developed the encryption logic using CryptoAPI (encryptToken() and decryptToken()), managed the structure and flow of the class-based system, and ensured that each module interacted smoothly. In addition, she designed and implemented the the FilingManager class which successfully stores data in csv format. 
Ghazia Shah integrated external libraries such as libcurl for sending OTPs and the Windows Biometric API for fingerprint recognition. She also designed and implemented the OTPAuth, FingerPrintAuth, and PasswordAuth authentication classes, ensuring seamless fallback logic in the loginWithFallback() method


