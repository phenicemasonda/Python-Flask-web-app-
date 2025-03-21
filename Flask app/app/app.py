from flask import Flask, render_template, request, redirect, url_for, session, flash
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for session management

# Dummy database of users
users = {
    "admin": {"password": "admin123", "role": "owner"},
    "reader": {"password": "reader123", "role": "reader"},
    "contributor": {"password": "contributor123", "role": "contributor"},
}

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Check if the username exists in the dummy database
        if username in users and users[username]["password"] == password:
            session["username"] = username
            session["role"] = users[username]["role"]  # Set the user's role
            flash("Login successful!", "success")
            return redirect(url_for("vms"))
        else:
            flash("Invalid username or password", "error")

    return render_template("login.html")


@app.route("/vms")
def vms():
    if "username" not in session:
        flash("Please log in to access this page.", "error")
        return redirect(url_for("login"))

    # Your existing logic for the VMs page
    vm_list = []  # Replace with actual logic to fetch VMs
    return render_template("vms.html", vms=vm_list, role=session["role"])

@app.route("/files")
def files():
    if "username" not in session:
        flash("Please log in to access this page.", "error")
        return redirect(url_for("login"))

    # Your logic to fetch and display files
    container_client = blob_service_client.get_container_client(container_name)
    blob_list = container_client.list_blobs()
    return render_template("files.html", blobs=blob_list, role=session["role"])

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)



    
# from flask import Flask, render_template, request, redirect, url_for, session, flash
# from azure.identity import DefaultAzureCredential
# from azure.mgmt.compute import ComputeManagementClient
# from azure.mgmt.storage import StorageManagementClient
# from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient, generate_blob_sas, BlobSasPermissions
# from azure.mgmt.resource import ResourceManagementClient
# from azure.mgmt.keyvault import KeyVaultManagementClient
# from azure.keyvault.secrets import SecretClient
# import os
# import uuid
# from datetime import datetime, timedelta
# import settings

# app = Flask(__name__)
# app.secret_key = os.urandom(24)

# # Azure Configuration
# # Explicitly define the variables from settings
# subscription_id = settings.subscription_id
# resource_group = settings.resource_group
# storage_account_name = settings.storage_account_name
# container_name = settings.container_name
# key_vault_name = settings.key_vault_name
# secret_name = settings.secret_name


# credential = DefaultAzureCredential()
# compute_client = ComputeManagementClient(credential, subscription_id)
# storage_client = StorageManagementClient(credential, subscription_id)
# resource_client = ResourceManagementClient(credential, subscription_id)
# keyvault_client = KeyVaultManagementClient(credential, subscription_id)
# keyvault_url = f"https://{key_vault_name}.vault.azure.net/"
# secret_client = SecretClient(vault_url=keyvault_url, credential=credential)

# blob_service_client = BlobServiceClient(f"https://{storage_account_name}.blob.core.windows.net", credential=credential)

# # RBAC and MAC policies (simplified examples)

# user_roles = {
#     "reader": ["list_vms", "list_files"],
#     "contributor": ["list_vms", "start_vm", "stop_vm", "list_files", "upload_file", "share_file"],
#     "owner": ["list_vms", "start_vm", "stop_vm", "delete_vm", "list_files", "upload_file", "share_file", "delete_file", "manage_permissions"],
# }

# file_permissions = {}  # DAC: {file_name: {user: permission}}
# file_labels = {} # MAC: {file_name: "sensitive" or "public"}

# def check_permission(user_role, action):
#     if user_role in user_roles and action in user_roles[user_role]:
#         return True
#     return False

# def check_file_access(user, file_name, permission):
#     if file_name in file_permissions and user in file_permissions[file_name]:
#         if permission in file_permissions[file_name][user]:
#             return True
#     return False

# def check_mac_policy(file_name, user_role):
#     if file_name in file_labels and file_labels[file_name] == "sensitive":
#         if user_role != "owner": #example policy
#             return False
#     return True

# # ABAC example
# def check_abac(user, resource, action, environment):
#     if user == "admin" and action == "delete" and resource == "vm":
#       return True
#     if user == "contributor" and action == "start" and resource=="vm" and environment=="dev":
#       return True
#     return False

# def get_secret():
#     try:
#         secret = secret_client.get_secret(secret_name)
#         return secret.value
#     except Exception as e:
#         flash(f"Error retrieving secret: {e}", "error")
#         return None


# # Dummy database of users
# users = {
#     "admin": {"password": "admin123", "role": "owner"},
#     "reader": {"password": "reader123", "role": "reader"},
#     "contributor": {"password": "contributor123", "role": "contributor"},
# }


# @app.route("/login", methods=["GET", "POST"])
# def signin():
#     if request.method == "POST":
#         username = request.form["username"]
#         password = request.form["password"]

#         # Check if the username exists in the dummy database
#         if username in users and users[username]["password"] == password:
#             session["username"] = username
#             session["role"] = users[username]["role"]  # Set the user's role
#             flash("Login successful!", "success")
#             return redirect(url_for("vms"))
#         else:
#             flash("Invalid username or password", "error")

#     return render_template("login.html")


# @app.route("/", methods=["GET", "POST"])
# def login():
#     if request.method == "POST":
#         username = request.form["username"]
#         password = request.form["password"] #In real world use secure authentication
#         session["username"] = username
#         if username == "reader":
#             session["role"] = "reader"
#         elif username == "contributor":
#             session["role"] = "contributor"
#         elif username == "owner":
#             session["role"] = "owner"
#         elif username == "admin":
#             session["role"] = "owner" #Admin has all permissions
#         else:
#             session["role"] = "reader" #default
#         return redirect(url_for("vms"))
#     return render_template("login.html")

# @app.route("/vms")
# def vms():
#     if "username" not in session:
#         return redirect(url_for("login"))
#     if not check_permission(session["role"], "list_vms"):
#         flash("Permission denied", "error")
#         return redirect(url_for("login"))

#     vm_list = compute_client.virtual_machines.list(resource_group)
#     return render_template("vms.html", vms=vm_list, role=session["role"])

# @app.route("/start_vm/<vm_name>")
# def start_vm(vm_name):
#     if "username" not in session:
#         return redirect(url_for("login"))
#     if not check_permission(session["role"], "start_vm"):
#         flash("Permission denied", "error")
#         return redirect(url_for("vms"))
#     if check_abac(session["username"], "vm", "start", "dev"):
#       compute_client.virtual_machines.begin_start(resource_group, vm_name)
#       flash(f"VM {vm_name} started", "success")
#     else:
#       flash("ABAC Policy Denied", "error")
#     return redirect(url_for("vms"))

# @app.route("/stop_vm/<vm_name>")
# def stop_vm(vm_name):
#     if "username" not in session:
#         return redirect(url_for("login"))
#     if not check_permission(session["role"], "stop_vm"):
#         flash("Permission denied", "error")
#         return redirect(url_for("vms"))

#     compute_client.virtual_machines.begin_deallocate(resource_group, vm_name)
#     flash(f"VM {vm_name} stopped", "success")
#     return redirect(url_for("vms"))

# @app.route("/delete_vm/<vm_name>")
# def delete_vm(vm_name):
#     if "username" not in session:
#         return redirect(url_for("login"))
#     if not check_permission(session["role"], "delete_vm"):
#         flash("Permission denied", "error")
#         return redirect(url_for("vms"))
#     if check_abac(session["username"], "vm", "delete", ""):
#         compute_client.virtual_machines.begin_delete(resource_group, vm_name)
#         flash(f"VM {vm_name} deleted", "success")
#     else:
#       flash("ABAC policy denied", "error")
#     return redirect(url_for("vms"))

# @app.route("/files", methods=["GET", "POST"])
# def files():
#     if "username" not in session:
#         return redirect(url_for("login"))
#     if not check_permission(session["role"], "list_files"):
#         flash("Permission denied", "error")
#         return redirect(url_for("login"))

#     container_client = blob_service_client.get_container_client(container_name)
#     blob_list = container_client.list_blobs()
#     return render_template("files.html", blobs=blob_list, role=session["role"])

# @app.route("/upload", methods=["POST"])
# def upload():
#     if "username" not in session:
#         return redirect(url_for("login"))
#     if not check_permission(session["role"], "upload_file"):
#         flash("Permission denied", "error")
#         return redirect(url_for("files"))

#     file = request.files["file"]
#     if file:
#         blob_client = blob_service_client.get_blob_client(container=container_name, blob=file.filename)
#         blob_client.upload_blob(file)
#         file_permissions[file.filename] = {session["username"]: ["read", "write"]} #owner has all perms
#         file_labels[file.filename] = "public" #default label
#         flash("File uploaded successfully", "success")
#     return redirect(url_for("files"))

# @app.route("/share/<file_name>", methods=["GET", "POST"])
# def share(file_name):
#     if "username" not in session:
#         return redirect(url_for("login"))
#     if not check_permission(session["role"], "share_file"):
#         flash("Permission denied", "error")
#         return redirect(url_for("files"))

#     if request.method == "POST":
#         user_to_share = request.form["user_to_share"]
#         permission = request.form["permission"]
#         if file_name not in file_permissions:
#             file_permissions[file_name] = {}
#         if user_to_share not in file_permissions[file_name]:
#             file_permissions[file_name][user_to_share] = []
#         file_permissions[file_name][user_to_share].append(permission)
#         flash(f"File {file_name} shared with {user_to_share} with {permission} permission", "success")
#         return redirect(url_for("files"))

#     return render_template("share.html", file_name=file_name)

# @app.route("/delete/<file_name>")
# def delete_file(file_name):
#     if "username" not in session:
#         return redirect(url_for("login"))
#     if not check_permission(session["role"], "delete_file"):
#         flash("Permission denied", "error")
#         return redirect(url_for("files"))
#     if not check_file_access(session["username"], file_name, "write"):
#         flash("Permission denied to delete this file", "error")
#         return redirect(url_for("files"))

#     blob_client = blob_service_client.get_blob_client(container=container_name, blob=file_name)
#     blob_client.delete_blob()
#     if file_name in file_permissions:
#         del file_permissions[file_name]
#     if file_name in file_labels:
#       del file_labels[file_name]
#     flash(f"File {file_name} deleted", "success")
#     return redirect(url_for("files"))

# @app.route("/manage_permissions/<file_name>", methods=["GET", "POST"])
# def manage_permissions(file_name):
#     if "username" not in session:
#         return redirect(url_for("login"))
#     if not check_permission(session["role"], "manage_permissions"):
#         flash("Permission denied", "error")
#         return redirect(url_for("files"))
#     if not check_file_access(session["username"], file_name, "write"):
#         flash("Permission denied to manage this file's permissions", "error")
#         return redirect(url_for("files"))

#     if request.method == "POST":
#         user_to_change = request.form["user_to_change"]
#         new_permissions = request.form.getlist("permissions")
#         if file_name in file_permissions and user_to_change in file_permissions[file_name]:
#             file_permissions[file_name][user_to_change] = new_permissions
#             flash(f"Permissions for {user_to_change} updated", "success")
#         return redirect(url_for("files"))

#     return render_template("manage_permissions.html", file_name=file_name, permissions=file_permissions.get(file_name, {}))

# @app.route("/change_label/<file_name>", methods=["GET", "POST"])
# def change_label(file_name):
#     if "username" not in session:
#         return redirect(url_for("login"))
#     if not check_permission(session["role"], "manage_permissions"):
#         flash("Permission denied", "error")
#         return redirect(url_for("files"))
#     if not check_file_access(session["username"], file_name, "write"):
#         flash("Permission denied to manage this file's label", "error")
#         return redirect(url_for("files"))
#     if request.method == "POST":
#         new_label = request.form["label"]
#         if file_name in file_labels:
#             file_labels[file_name] = new_label
#             flash(f"Label for {file_name} updated to {new_label}", "success")
#         return redirect(url_for("files"))
#     return render_template("change_label.html", file_name=file_name, current_label=file_labels.get(file_name, "public"))

# @app.route("/download/<file_name>")
# def download_file(file_name):
#   if "username" not in session:
#     return redirect(url_for("login"))
#   if not check_permission(session['role'], 'list_files'):
#     flash("Permission denied", "error")
#     return redirect(url_for("files"))

#   if not check_file_access(session['username'], file_name, 'read') and session['role'] != 'owner':
#     flash("Permission Denied to download this file", "error")
#     return redirect(url_for("files"))

#   blob_client = blob_service_client.get_blob_client(container=container_name, blob=file_name)
#   blob_sas = generate_blob_sas(
#       account_name=storage_account_name,
#       container_name=container_name,
#       blob_name=file_name,
#       account_key=blob_client.credential.account_key,
#       permission=BlobSasPermissions(read=True),
#       expiry=datetime.utcnow() + timedelta(hours=1)
#   )
#   download_url = f"https://{storage_account_name}.blob.core.windows.net/{container_name}/{file_name}?{blob_sas}"
#   return redirect(download_url)

# if __name__ == "__main__":
#     app.run(debug=True) 

