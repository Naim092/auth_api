Roles and Permissions for Auth API
Admin can register using the /admin/register endpoint.

1. Admin:
 - Register Companies: Can register new companies with details like name, address, username, and password.
 - View Companies: Can view the list of all registered companies.
 - Edit Companies: Can edit the details of any registered company.
 - Delete Companies: Can delete any registered company.
 - Register Users: Admins can also register new users.

2. User:
 - View Companies: Can only view the list of all registered companies.
 - Cannot Register: Users do not have permission to register new companies or other users.

3. Company:
 - Login: Can log in using the username and password provided during registration.
 - Edit Own Details: Can edit their own details (name, address, username, password).
 - Cannot Register: Companies cannot register new companies or other users.