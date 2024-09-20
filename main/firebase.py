import firebase_admin
from firebase_admin import credentials, firestore

cred = credentials.Certificate('E:\Community Pulse\community_pulse\community-pulse-9fd87-firebase-adminsdk-j788c-80cf771f8f.json')
firebase_admin.initialize_app(cred)

db = firestore.client()