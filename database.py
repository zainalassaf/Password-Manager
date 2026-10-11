import sqlite3
import getpass
from cryptography.exceptions import InvalidTag
from crypto import generate_salt,derive_key,encrypt_password,decrypt_password
# Connect to the SQLite database so we can execute database operations.
db=sqlite3.connect("info.db")
# Create a cursor to execute SQL commands and retrieve results.
cr=db.cursor()
# Create the accounts table only if it does not already exist.
# This prevents an error when the program starts again.
# Use id as the primary key to uniquely identify each account.
# AUTOINCREMENT lets SQLite generate a new ID for each account automatically.
# Store the encrypted password as BLOB because encrypted data is binary bytes.
# Store the nonce as BLOB because it is generated and stored as binary bytes.
cr.execute("""CREATE TABLE if not exists accounts(
id INTEGER PRIMARY KEY AUTOINCREMENT,
website text,
gmail text,
encrypted_password BLOB,
nonce BLOB
)
""")
# The vault stores only one row, so AUTOINCREMENT is not needed.
# The fixed ID allows us to identify and update the vault record.
# The salt is required with the master password to derive the AES key.
# NOT NULL ensures that the salt is always available.
# The verification ciphertext and nonce are required
# to verify the master password during authentication.
# NOT NULL ensures that both values are always available.
# Use id as the primary key to uniquely identify the vault record.
# The vault is designed to contain only one record with a fixed ID.
cr.execute("""CREATE TABLE if not exists vault(
id INTEGER PRIMARY KEY,
salt BLOB NOT NULL,
verification_ciphertext BLOB NOT NULL,
verification_nonce BLOB NOT NULL
)
""")
db.commit()
# Use a separate function to avoid repeating the master password input code.
# This keeps the code clean and reusable.
def get_master_password():
    # Use getpass to hide the master password while the user types it.
    # This prevents the password from being displayed on the screen.
    master_password=getpass.getpass("Enter Master Password :")
    # Return the master password so the calling function can use it.
    return master_password
# Authenticate the user by deriving an AES key from the master password
# and verifying it using the encrypted vault verification data.
def authenticate_vault():
    # Check if the vault has data.
    cr.execute("SELECT * FROM vault")
    # Get one row from the vault table.
    vault_info=cr.fetchone()
    # Check if the vault table is empty.
    if vault_info is None:
        master_password_value = get_master_password() 
        #Because I use it with the master password to derive the AES key.   
        salt=generate_salt()
        AES_key=derive_key(master_password_value,salt)
        # Encrypt "VAULT_OK" to verify the master password later.
        ciphertext,nonce=encrypt_password("VAULT_OK",AES_key)
        # Store the salt, ciphertext, and nonce because we need them for authentication.
        # These values are not secret.
        cr.execute("INSERT INTO vault(salt,verification_ciphertext,verification_nonce) VALUES (?,?,?) ",(salt,ciphertext,nonce))
        # Save the changes to the database.
        db.commit()
        # Return the AES key so the program can use it after authentication.
        return AES_key
    else:     
        master_password_2=get_master_password()
        # Derive the AES key using the stored salt.
        AES_key_2=derive_key(master_password_2,vault_info[1])
        try:
            # Decrypt the verification data using the derived AES key.
            # If it returns "VAULT_OK", the master password is correct.
            plaintext=decrypt_password(vault_info[2],vault_info[3],AES_key_2)
            # Check if the decrypted data is the correct verification value.
            if plaintext=="VAULT_OK":
                return AES_key_2
            else:
                 return None
        # Return None if the verification fails.
        except InvalidTag:
            return None
def update_vault_credentials(salt,ciphertext,nonce):
     cr.execute("UPDATE vault SET salt=?,verification_ciphertext=?,verification_nonce=? WHERE id=?",(salt,ciphertext,nonce,1))
# We close the database connection only when the program exits.
def commit_and_close():
    db.commit()
    db.close()
# We use it to save the changes without closing the database connection.
def commit_transaction():
     db.commit()
def insert_account(website_name,gmail,ciphertext,nonce):
    cr.execute("INSERT INTO accounts(website,gmail,encrypted_password,nonce) VALUES(?,?,?,?)",(website_name,gmail,ciphertext,nonce))
    db.commit()
def get_all_accounts():
        account_info=cr.execute("SELECT * FROM accounts")
        account_info=cr.fetchall()
        return account_info
def search_account_by_website(website_info):
    cr.execute("SELECT * FROM accounts WHERE website=?",(website_info,))
    find=cr.fetchall()
    return find
def update_account_with_commit(ciphertext,nonce,account_id):
        cr.execute("UPDATE accounts SET encrypted_password=?, nonce=? WHERE id=?",(ciphertext,nonce,account_id,))
        db.commit()
# We use the version without commit when the update is part of a larger transaction
def update_account_without_commit(ciphertext,nonce,account_id):
        cr.execute("UPDATE accounts SET encrypted_password=?, nonce=? WHERE id=?",(ciphertext,nonce,account_id,))
def delete_account(account_id):
        cr.execute("DELETE FROM accounts WHERE id=?",(account_id,))
        db.commit()
def fetch_account_id(account_id):
        cr.execute("SELECT id FROM accounts WHERE id=?",(account_id,))
        find=cr.fetchone()
        return find
def fetch_all_ids():
     cr.execute("SELECT id FROM accounts")
     find=cr.fetchall()
     return find
# A transaction makes sure all changes succeed together or are rolled back if something fails.
def begin_transaction():
    cr.execute("BEGIN TRANSACTION")
# Undo all changes if the transaction fails.
def rollback():
    db.rollback()