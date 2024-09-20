from django.shortcuts import redirect, render
from firebase_admin import firestore, db, storage
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password
import datetime
from django.contrib.messages.storage.fallback import FallbackStorage
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.utils.encoding import force_str
from .decorators import check_session
import hashlib
import time
from datetime import datetime
from django.utils import timezone
from torch import StorageBase


def simple_token_generator(email):
    timestamp = str(time.time()).encode('utf-8')
    return hashlib.sha256(email.encode('utf-8') + timestamp).hexdigest()

def signup(request):
    if request.method == "POST":
        name = request.POST['name']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm-password']
        terms = request.POST.get('terms-and-conditions', 'off')
        
        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return redirect('/signup/')

        if terms != 'on':
            messages.error(request, "Please accept our terms and conditions!")
            return redirect('/signup/')
        
        hashed_password = make_password(password)
        current_time = datetime.now()
        
        ref = db.reference('users')
        users_ref = ref.child(email.replace('.', ','))
        if users_ref.get():
            messages.error(request, 'A user with this email ID already exists.')
            return redirect('/signup/')

        users_ref.set({
            'name': name,
            'email': email,
            'password': hashed_password,
            'account_created': current_time.strftime("%Y-%m-%d %H:%M:%S"),
            'last_login' : current_time.strftime("%Y-%m-%d %H:%M:%S"),
        })

        messages.success(request, 'Successfully registered. Please log in.')
        return redirect('/signin/')

    return render(request, 'signup.html')

def home(request):
    events_ref = db.reference('events')
    rsvps_ref = db.reference('rsvps')

    current_date = datetime.now().strftime('%Y-%m-%d')

    events_snapshot = events_ref.get()

    upcoming_and_popular_events = []
    for event_id, event_val in events_snapshot.items():
        start_date = event_val.get('start_date')
        end_date = event_val.get('end_date', '')

        if start_date >= current_date or (start_date <= current_date <= end_date):
            event_rsvps_snapshot = rsvps_ref.order_by_child('event_id').equal_to(event_id).get()
            rsvp_count = len(event_rsvps_snapshot) if event_rsvps_snapshot else 0
            
            upcoming_and_popular_events.append({
                **event_val, 
                'id': event_id, 
                'rsvp_count': rsvp_count
            })
    
    upcoming_and_popular_events.sort(key=lambda x: (-x['rsvp_count'], x['start_date']))
    
    upcoming_and_popular_events = upcoming_and_popular_events[:4]

    return render(request, 'index.html', {'events': upcoming_and_popular_events})


def signin(request):
    if request.method == "POST":
        email = request.POST.get('email')
        password = request.POST.get('password')

        ref = db.reference('users')
        user_ref = ref.child(email.replace('.', ','))
        user_data = user_ref.get()

        if not user_data:
            messages.error(request, 'No user found with the provided credentials.')
            return redirect('/signin/')

        if check_password(password, user_data['password']):
            request.session['user_info'] = {
                'email': email,
                'name': user_data.get('name', 'Unknown')  
            }
            user_ref.update({
                'last_login': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
            messages.success(request, 'Successfully logged in.')
            return redirect('/dashboard/')
        else:
            messages.error(request, 'Incorrect password.')
            return render(request, 'signin.html')
    else:
        return render(request, 'signin.html')

def verify_token(email, provided_token):
    user_id = email.replace('.', ',')  # Firebase key
    ref = db.reference('users')
    user_ref = ref.child(user_id)
    user_data = user_ref.get()
    stored_token = user_data.get('reset_token', '')

    return stored_token == provided_token

def forgot_password(request):
    if request.method == 'POST':
        print("Forgot Password view reached")
        email = request.POST.get('email')
        ref = db.reference('users')
        user_ref = ref.child(email.replace('.', ','))
        user_data = user_ref.get()

        if user_data:
            token = simple_token_generator(email)
            user_ref.update({'reset_token': token})
            uid = urlsafe_base64_encode(force_bytes(email))
            password_reset_link = f"http://127.0.0.1:8000/reset_password/{uid}/{token}/"
            
            site_name = "Community Pulse"
            domain = "communitypulse.ca"
            
            email_context = {
                'email': email,  
                'domain': domain,
                'site_name': site_name,
                'reset_link': password_reset_link,  
            }
            
            email_body = render_to_string('password_reset_email.html', email_context)

            
            try:
                send_mail(
                    'Password Reset Request',
                    email_body,
                    'communitypulse@gmail.com',
                    [email],
                    fail_silently=False,
                    html_message=email_body,  
                )
                messages.success(request, 'A password reset link has been sent to your email.')
                return redirect('/signin/')
            except Exception as e:
                print(e)
                messages.error(request, 'There was an error sending the email.')

        else:
            messages.error(request, 'Email does not exist.')

    return render(request, 'forgot_password.html')

def reset_password(request, uidb64, token):
    try:
        email = force_str(urlsafe_base64_decode(uidb64))
    except (TypeError, ValueError, OverflowError):
        email = None

    if email is not None and verify_token(email, token):
        if request.method == 'POST':
            new_password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

            if new_password and new_password == confirm_password:
                user_id = email.replace('.', ',')  
                ref = db.reference('users')
                user_ref = ref.child(user_id)
                
                user_ref.update({
                    'password': make_password(new_password),
                    'reset_token': None  
                })

                messages.success(request, 'Your password has been set. You may go ahead and log in now.')
                return redirect('/signin/')
            else:
                messages.error(request, 'Passwords do not match.')
        return render(request, 'reset_password.html', {'uid': uidb64, 'token': token})
    else:
        messages.error(request, 'The reset password link is invalid, possibly because it has already been used. Please request a new link.')
        return redirect('/forgot_password/')

def clear_messages(request):
    storage = FallbackStorage(request)
    for message in storage:
        pass
    
@check_session
def dashboard(request):
    user_info = request.session.get('user_info')
    if not user_info:
        messages.error(request, 'You need to login to view the dashboard.')
        return redirect('/signin/')

    user_email = user_info['email']
    today = timezone.now().strftime('%Y-%m-%d')
    events_ref = db.reference('events')
    rsvps_ref = db.reference('rsvps')

    all_events = events_ref.get() or {}
    user_rsvps = rsvps_ref.order_by_child('user_email').equal_to(user_email).get() or {}
    
    attended_events_count = 0
    confirmed_events_count = 0
    posted_events_count = 0
    recently_explored_events = []

    user_rsvp_event_ids = {rsvp.get('event_id') for rsvp in user_rsvps.values()} if user_rsvps else set()

    for event_id, event in all_events.items():
        if event and 'start_date' in event and 'end_date' in event:
            event_date = event.get('end_date')
            if event_date:  
                if event_id in user_rsvp_event_ids:
                    if event_date < today:
                        attended_events_count += 1
                    elif event_date >= today:
                        confirmed_events_count += 1
                if event.get('creator') == user_email:
                    posted_events_count += 1

                event['id'] = event_id  
                if event['end_date'] >= today:
                    recently_explored_events.append(event)

    if recently_explored_events:
        recently_explored_events.sort(key=lambda x: x['start_date'])
        recently_explored_events = recently_explored_events[:5]

    context = {
        'user_info': user_info,
        'attended_events_count': attended_events_count,
        'confirmed_events_count': confirmed_events_count,
        'posted_events_count': posted_events_count,
        'recently_explored_events': recently_explored_events,
    }

    return render(request, 'dashboard.html', context)


def logout(request):
    request.session.flush()
    storage = messages.get_messages(request)
    for message in storage:
        storage.used = True
    messages.success(request, 'You have been logged out successfully.')
    return redirect('/signin/')  

@check_session
def addevent(request):
    user_info = request.session.get('user_info', {})
    if request.method == "POST":
        event_name = request.POST.get('name')
        event_category = request.POST.get('category')
        start_date = request.POST.get('st_date')
        end_date = request.POST.get('en_date')  
        event_type = request.POST.get('event_type')
        event_price = request.POST.get('price') if event_type == 'paid' else '0'
        start_time = request.POST.get('st_time')
        end_time = request.POST.get('en_time')
        host_name = request.POST.get('host_name')
        country_code = request.POST.get('co_code')
        mobile = request.POST.get('mobile')
        location = request.POST.get('location')
        full_mobile = f"{country_code}{mobile}"

        event_poster = request.FILES.get('poster')
        poster_url = None
        if event_poster:
            bucket = storage.bucket()
            blob = bucket.blob(f'posters/{event_poster.name}')
            blob.upload_from_string(
                event_poster.read(),
                content_type=event_poster.content_type
            )
            blob.make_public()
            poster_url = blob.public_url

        ref = db.reference('events')
        new_event_ref = ref.push() 
        new_event_ref.set({
            'name': event_name,
            'category': event_category,
            'start_date': start_date,
            'end_date': end_date,
            'event_type': event_type,
            'price': event_price,
            'start_time': start_time,
            'end_time': end_time,
            'host_name': host_name,
            'mobile': full_mobile,
            'poster_url': poster_url,
            'location': location,
            'creator': user_info.get('email'),
        })

        messages.success(request, 'Event added successfully!')
        return redirect('/dashboard/')

    return render(request, 'addevent.html', {'user_info': user_info})


def events(request):
    search_made = False
    search_values = {
        'category': '',
        'date': '',
        'venue': '',
    }

    ref = db.reference('events')
    events_snapshot = ref.get() or {}
    events_list = []

    # Initialize user_date with a default value
    user_date = None

    today = timezone.now().strftime('%Y-%m-%d')

    if any(param in request.GET for param in ['name', 'date', 'venue']):
        search_made = True
        search_values['category'] = request.GET.get('name', '').lower()
        search_values['date'] = request.GET.get('date', '')
        search_values['venue'] = request.GET.get('venue', '').lower()
        # Set user_date only if 'date' is present and valid
        if search_values['date']:
            try:
                user_date = datetime.strptime(search_values['date'], '%Y-%m-%d').date()
            except ValueError:
                # Handle the case where date is invalid, e.g., log an error or set user_date to None
                pass

    for event_id, event_data in events_snapshot.items():
        start_date_str = event_data.get('start_date', '')
        end_date_str = event_data.get('end_date', '')
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date() if start_date_str else None
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date() if end_date_str else None

        matches_category = search_values['category'] in event_data.get('category', '').lower() if search_values['category'] else True
        matches_venue = search_values['venue'] in event_data.get('location', '').lower() if search_values['venue'] else True
        matches_date = True
        
        if user_date:
            matches_date = (start_date <= user_date <= end_date) if (start_date and end_date) else False

        if matches_category and matches_date and matches_venue:
            event_data['id'] = event_id
            events_list.append(event_data)

    return render(request, 'events.html', {
        'events': events_list,
        'search_made': search_made,
        'values': search_values
    })


@check_session
def confirm_rsvp(request, event_id):
    user_info = request.session.get('user_info')

    if not user_info:
        messages.error(request, 'You must be logged in to RSVP.')
        return redirect('signin') 

    user_email = user_info['email']
    rsvps_ref = db.reference('rsvps')

    existing_rsvp_ref = rsvps_ref.order_by_child('user_email').equal_to(user_email).get()

    if not any(rsvp.get('event_id') == event_id for rsvp in existing_rsvp_ref.values()):
        new_rsvp_ref = rsvps_ref.push()
        new_rsvp_ref.set({
            'user_email': user_email,
            'event_id': event_id,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        messages.success(request, 'Your RSVP has been confirmed!')
    else:
        messages.info(request, 'You have already RSVPed to this event.')

    return redirect('events')  

@check_session
def post_event(request):
    return redirect('/addevent/')

@check_session
def posted_events(request):
    user_info = request.session.get('user_info', {})
    user_email = user_info['email']
    events_ref = db.reference('events')
    rsvps_ref = db.reference('rsvps')
    
    all_events = events_ref.get() or {}
    all_rsvps = rsvps_ref.get() or {}
    
    user_posted_events_with_rsvp_counts = []
    
    for event_id, event in all_events.items():
        if event.get('creator') == user_email:
            rsvp_count = sum(1 for rsvp in all_rsvps.values() if isinstance(rsvp, dict) and rsvp.get('event_id') == event_id)
            event_with_rsvp_count = event.copy()
            event_with_rsvp_count['rsvp_count'] = rsvp_count
            event_with_rsvp_count['id'] = event_id  
            user_posted_events_with_rsvp_counts.append(event_with_rsvp_count)
    
    context = {
        'user_info': user_info,
        'posted_events': user_posted_events_with_rsvp_counts,
    }
    return render(request, 'posted_events.html', context)



@check_session
def confirmed_events(request):
    user_info = request.session.get('user_info')
    if not user_info:
        messages.error(request, 'You need to login to view this page.')
        return redirect('/signin/')
    
    user_email = user_info['email']
    today = timezone.now().strftime('%Y-%m-%d')
    rsvps_ref = db.reference('rsvps')
    events_ref = db.reference('events')

    user_rsvps = rsvps_ref.order_by_child('user_email').equal_to(user_email).get() or {}
    confirmed_event_ids = {rsvp.get('event_id') for rsvp in user_rsvps.values()}
    
    confirmed_events = []
    for event_id in confirmed_event_ids:
        event = events_ref.child(event_id).get()
        if event and 'end_date' in event and event['end_date'] >= today:
            event['id'] = event_id  
            confirmed_events.append(event)

    context = {
        'user_info': user_info,
        'confirmed_events': confirmed_events,
    }

    return render(request, 'confirmed_events.html', context)

@check_session
def cancel_rsvp(request, event_id):
    user_info = request.session.get('user_info', {})
    user_email = user_info['email']
    rsvps_ref = db.reference('rsvps')

    user_rsvps = rsvps_ref.order_by_child('user_email').equal_to(user_email).get()
    rsvp_to_cancel = {key: val for key, val in user_rsvps.items() if val.get('event_id') == event_id}

    if rsvp_to_cancel:
        rsvp_key = next(iter(rsvp_to_cancel.keys()))
        rsvps_ref.child(rsvp_key).delete()
        messages.success(request, 'Your RSVP has been canceled.')
    else:
        messages.error(request, 'No RSVP found to cancel.')

    return redirect('confirmed_events')

@check_session
def delete_event(request, event_id):
    user_info = request.session.get('user_info', {})
    if not user_info:
        messages.error(request, 'You need to login to perform this action.')
        return redirect('/signin/')
    
    events_ref = db.reference('events')
    event_ref = events_ref.child(event_id)

    event_ref.delete()

    messages.success(request, 'Event deleted successfully.')
    return redirect('posted_events')