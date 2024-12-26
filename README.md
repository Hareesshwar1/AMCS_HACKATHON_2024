Project Overview:
The Personal Data Vault is a secure web application designed for uploading, categorizing, and encrypting sensitive files. Users can classify their documents into predefined categories, upload them, and securely encrypt the data using an integrated backend.

File Upload:

Supports multiple file uploads.
Requires categorization before submission.
Categorization:

Files can be tagged as:
Financial Documents
Passwords
Personal Files
Encryption:

Uploaded files are sent to the backend for encryption.
Utilizes fetch API to transmit file data securely to the server.
Dynamic File Management:

View, remove, and manage uploaded files in a real-time list before submission.
Technologies Used:

Frontend: HTML, CSS, JavaScript (for dynamic interactions).
Backend: API endpoint (http://127.0.0.1:5000/encrypt) for encryption (not included in this repository).
How It Works:

Upload Files: Select files and assign them to a category.
Preview List: View the file details in the dynamically generated list.
Submit for Encryption: Files are read as ArrayBuffer and sent to the backend for secure encryption.
Setup and Usage:

Clone or download this repository.
Host the index.html file in a local or remote server.
Ensure the backend service for encryption (http://127.0.0.1:5000/encrypt) is running.
Open the application in a browser, upload files, assign categories, and submit.
