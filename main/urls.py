from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'), 
    path('signup/',views.signup,name='signup'),
    path('signin/',views.signin,name='signin'),
    path('forgot_password/',views.forgot_password,name='forgot_password'),
    path('reset_password/<uidb64>/<token>/',views.reset_password,name='reset_password'),
    path('dashboard/',views.dashboard,name='dashboard'),
    path('logout/', views.logout, name='logout'),
    path('addevent/', views.addevent, name='addevent'),
    path('events/', views.events, name='events'),
    path('posted_events/', views.posted_events, name='posted_events'),
    path('confirmed_events/', views.confirmed_events, name='confirmed_events'),
    path('confirm_rsvp/<str:event_id>/', views.confirm_rsvp, name='confirm_rsvp'),
    path('post_event/', views.post_event, name='post_event'),
    path('cancel_rsvp/<str:event_id>/', views.cancel_rsvp, name='cancel_rsvp'),
    path('delete_event/<str:event_id>/', views.delete_event, name='delete_event'),
]
