# userAuthenticate
Authenticate username and passwords by having a sign up page. The data is sent to a mongoDB database where the password is serialized using bcrypt hash. The index page has a log in function that checks our DB rows to check if usernames and serialized passwords match user input. Tools also used include express, nodemon, passport.js, and express-sessions to store user cookies to browser. 
