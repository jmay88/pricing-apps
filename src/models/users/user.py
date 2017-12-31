import uuid
import src.models.users.errors as UserErrors
from src.common.database import Database
from src.common.utils import Utils
from src.models.alerts.alert import Alert
import src.models.users.constants as UserConstants


class User(object):
    def __init__(self, email, password, _id=None):
        self.email = email
        self.password = password
        self._id = uuid.uuid4().hex if _id is None else _id

    def __repr__(self):
        return "<User {}>".format(self.email)

    @staticmethod
    def is_login_valid(email, password):
        """
        This method verifies and email and password combination is valid or not,
        check that the email exist and the password associated to the email is correct
        :param email: The user's email
        :param password: A sha512 hash password
        :return: True if valid, False otherwise
        """

        user_data = Database.find_one(UserConstants.COLLECTION, {"email":email}) # password in sha512 > pbkdf2_sha512
        if user_data is None:
            # tell the user that their email doesnt exist
            raise UserErrors.UserNotExistError("Your user does not exist")
        if not Utils.check_hashed_password(password, user_data['password']):
            # tell the user that password is wrong
            raise UserErrors.IncorrectPasswordError("Your password is incorrect")

        return True

    @staticmethod
    def register_user(email, password):
        """
        This method register user using email and password.
        The password already come encrypte as sha512
        :param email: user's email (might be invalid)
        :param password: sha512 hashed password
        :return: True if registered successfully, False otherwise (exceptation can also be raised)
        """
        user_data = Database.find_one(UserConstants.COLLECTION, {"email": email})

        if user_data is not None:
            # tell user they are already registered
            raise UserErrors.UserAlreadyRegisteredError("The email you used to register already exists")
        if not Utils.email_is_valid(email):
            # Tell user their email is not constructed propoerly
            raise UserErrors.InvalidEmailError("The email does not have valid format")

        User(email, Utils.hash_password(password)).save_to_db()

        return True

    def save_to_db(self):
        Database.insert(UserConstants.COLLECTION, self.json())

    def json(self):
        return {
            "_id" : self._id,
            "email" : self.email,
            "password" : self.password
        }

    @classmethod
    def find_by_email(cls, email):
        return cls(**Database.find_one(UserConstants.COLLECTION, {'email': email}))

    def get_alert(self):
        return Alert.find_by_user_email(self.email)


