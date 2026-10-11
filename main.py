import database
import getpass
from crypto import encrypt_password,decrypt_password,derive_key
from cryptography.exceptions import InvalidTag
import re
class Account:
    def check_accounts():
        Warning_message = input("Enter 2 to view all accounts or any numbers to skip : ")
        find = database.fetch_all_ids()
        if find == []:
            print("Your Data Base Is Empty")
            return False
        if Warning_message == "2":
            Account.get_account()
        return True       
    def add_account():
        website_name=input("Enter Website name : ").strip()
        if(website_name==""):
            print("Invalid Name, try again.")
            return
        gmail=input("Enter Your Gmail : ").strip()
        emails = r"^[a-zA-Z0-9]+@[a-zA-Z0-9]+\.com$"
        if re.match(emails,gmail):
            print("Valid Email")
        else:
            print("Invalid Email")
            return
        password=getpass.getpass("Enter Your Password : ").strip()
        if password=="":
            print("Invalid Password")
            return
        ciphertext,nonce=encrypt_password(password,vault_key)
        database.insert_account(website_name,gmail,ciphertext,nonce)
        print("___Account Added Successfully! ___")
    def get_account():
        account_info=database.get_all_accounts()
        if account_info==[]:
            print("No account found")
        else:
            for info in account_info:
                print(f"ID ==> {info[0]}",end="||")
                print(f"Website ==> {info[1]}",end="||")
                print(f"Gmail ==> {info[2]}",end="||")
                password=decrypt_password(info[3],info[4],vault_key)
                print(f"password ==> {password}")
    def search_account():
        website_info=input("Enter Website name : ")
        find=database.search_account_by_website(website_info)
        if find==[]:
            print("No account found for this website.")
        else:
            for info in find:
                print(f"ID => {info[0]}")
                print(f"Website => {info[1]}")
                print(f"Gmail => {info[2]}") 
                password=decrypt_password(info[3],info[4],vault_key)
                print(f"password ==> {password}")
    def update_account():
        test=Account.check_accounts()
        if not test:
            return 0
        while True:
            try:
                account_id=int(input("Enter Account ID : "))
                break
            except ValueError:
                print("try again,Enter a number :")
        find=database.fetch_account_id(account_id)
        if find is None:
            print("Your ID is Wrong ,try again")
        else:
            new_password=getpass.getpass("Enter the new password :")
            if not new_password:
                return 0
            ciphertext,nonce=encrypt_password(new_password,vault_key)
            database.update_account_with_commit(ciphertext,nonce,account_id)
    def delete_account():
        test=Account.check_accounts()
        if not test:
            return 0
        while True:
            try:
                account_id=int(input("Enter Account ID :"))
                break
            except ValueError:
                print("try again,Enter a number :")
        find=database.fetch_account_id(account_id)
        if find is None:
            print("Your ID is Wrong ,try again")
        else:
            database.delete_account(account_id)
            print("___Account Deleted Successfully! ___")
    def exit():
        database.commit_and_close()
    def change_master_password():
        global vault_key
        new_master_password = database.get_master_password()
        if new_master_password == "":
            print("Invalid Password")
            return
        Confirm_password = getpass.getpass("Confirm New Master Password:")
        if new_master_password != Confirm_password:
            print("No match")
            return
        try:
            # Derive a new AES key using the new master password and salt.
            database.begin_transaction()
            new_salt = database.generate_salt()
            new_vault_key = derive_key(new_master_password,new_salt )
            # Derive a new AES key using the new master password and salt.
            for account_info in database.get_all_accounts():
                password = decrypt_password(account_info[3],account_info[4],vault_key)
                ciphertext, nonce = encrypt_password(password,new_vault_key)
                database.update_account_without_commit(ciphertext,nonce,account_info[0])
            # We create new verification data for the new master password.
            verification_ciphertext, verification_nonce = encrypt_password("VAULT_OK",new_vault_key)
            # Because the new password uses a new salt and a new key, we need new verification data.
            database.update_vault_credentials(new_salt,verification_ciphertext,verification_nonce)
            database.commit_transaction()
            # Update the current vault key after the database changes are saved.
            vault_key = new_vault_key
            print("Master Password Changed Successfully")
        except InvalidTag:
            # Undo the changes if the process fails.
            database.rollback()
            print("Failed to change Master Password at less on operation while encryption/decreption didn't complet")
        except database.sqlite3.Error:
            database.rollback()
            print("Failed to change Master Password due to a database error.")
vault_key=database.authenticate_vault()
if vault_key is None:
    print("Authentication failed.")
    Account.exit()
else:
    input_messege="""
    ===== Password Manager System ==== 
    1. Add account 
    2. Get account
    3. Search account 
    4. Update account 
    5. Delete account 
    6. Change master password
    7. Exit"
    What you want : 
    """
    admin=0
    while admin!=7:
        try:
            admin=int(input(input_messege))

            if admin not in range(1,8):
                print("Invalid input")
                continue
        except ValueError:
            print("Please Enter a number between 1 ==> 7")
            continue
        if admin==1:
            Account.add_account()
        elif admin==2:
            Account.get_account()
        elif admin==3:
            Account.search_account()
        elif admin==4:
            Account.update_account()
        elif admin==5:
            Account.delete_account()
        elif admin==6:
            Account.change_master_password()
        elif admin==7:
            Account.exit()