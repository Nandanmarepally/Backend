import json
import logging
import datetime

import jwt
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

logger = logging.getLogger(__name__)

from .models import Prompt, Tag, PasswordResetToken


# ── JWT helpers ───────────────────────────────────────────────────────────────
JWT_SECRET = settings.SECRET_KEY
JWT_ALGORITHM = 'HS256'
JWT_EXPIRY_HOURS = 24


def _make_token(user):
    payload = {
        'user_id': user.pk,
        'username': user.username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _decode_token(token: str):
    """Returns decoded payload or raises jwt.PyJWTError."""
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


def _get_token_from_request(request):
    auth = request.META.get('HTTP_AUTHORIZATION', '')
    if auth.startswith('Bearer '):
        return auth[7:]
    return None


def jwt_required(view_fn):
    """Decorator — returns 401 if a valid Bearer JWT is not present."""
    def wrapper(request, *args, **kwargs):
        token = _get_token_from_request(request)
        if not token:
            return JsonResponse({'error': 'Authentication required.'}, status=401)
        try:
            payload = _decode_token(token)
        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'Token expired.'}, status=401)
        except jwt.PyJWTError:
            return JsonResponse({'error': 'Invalid token.'}, status=401)
        request.jwt_payload = payload
        return view_fn(request, *args, **kwargs)
    wrapper.__name__ = view_fn.__name__
    return wrapper


# ── Prompt validation ─────────────────────────────────────────────────────────
def validate_prompt_data(data):
    """
    Validate prompt fields.
    Returns (errors_dict, None) or (None, cleaned_data).
    """
    errors = {}

    title = data.get('title', '').strip()
    content = data.get('content', '').strip()
    complexity_raw = data.get('complexity')
    tags_raw = data.get('tags', [])

    if not title:
        errors['title'] = 'Title is required.'
    elif len(title) < 3:
        errors['title'] = 'Title must be at least 3 characters.'
    elif len(title) > 255:
        errors['title'] = 'Title must be 255 characters or fewer.'

    if not content:
        errors['content'] = 'Content is required.'
    elif len(content) < 20:
        errors['content'] = 'Content must be at least 20 characters.'

    try:
        complexity = int(complexity_raw)
        if complexity < 1 or complexity > 10:
            errors['complexity'] = 'Complexity must be between 1 and 10.'
    except (TypeError, ValueError):
        errors['complexity'] = 'Complexity must be a number between 1 and 10.'
        complexity = None

    if not isinstance(tags_raw, list):
        errors['tags'] = 'Tags must be an array of strings.'
        tags_raw = []
    else:
        tags_raw = [t.strip().lower() for t in tags_raw if isinstance(t, str) and t.strip()]

    if errors:
        return errors, None

    return None, {
        'title': title,
        'content': content,
        'complexity': complexity,
        'tags': tags_raw,
    }


def _prompt_to_dict(prompt: Prompt) -> dict:
    return {
        'id': prompt.id,
        'title': prompt.title,
        'content': prompt.content,
        'complexity': prompt.complexity,
        'tags': list(prompt.tags.values_list('name', flat=True)),
        'created_at': prompt.created_at.isoformat(),
        'view_count': prompt.view_count,
    }


# ── Auth endpoints ─────────────────────────────────────────────────────────────

@csrf_exempt
@require_http_methods(['POST'])
def signup_view(request):
    """
    POST /api/auth/signup/
    Body: { "username": "...", "email": "...", "password": "...", "confirm_password": "..." }
    Returns: { "token": "<jwt>", "username": "..." }
    """
    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON body.'}, status=400)

    username = body.get('username', '').strip()
    email = body.get('email', '').strip()
    password = body.get('password', '')
    confirm_password = body.get('confirm_password', '')

    errors = {}

    # Username
    if not username:
        errors['username'] = 'Username is required.'
    elif len(username) < 3:
        errors['username'] = 'Username must be at least 3 characters.'
    elif len(username) > 150:
        errors['username'] = 'Username must be 150 characters or fewer.'
    elif User.objects.filter(username=username).exists():
        errors['username'] = 'Username is already taken.'

    # Email
    if not email:
        errors['email'] = 'Email is required.'
    else:
        try:
            validate_email(email)
        except ValidationError:
            errors['email'] = 'Enter a valid email address.'
        else:
            if User.objects.filter(email=email).exists():
                errors['email'] = 'An account with this email already exists.'

    # Password
    if not password:
        errors['password'] = 'Password is required.'
    elif len(password) < 8:
        errors['password'] = 'Password must be at least 8 characters.'

    # Confirm password
    if not confirm_password:
        errors['confirm_password'] = 'Please confirm your password.'
    elif password and confirm_password != password:
        errors['confirm_password'] = 'Passwords do not match.'

    if errors:
        return JsonResponse({'errors': errors}, status=422)

    user = User.objects.create_user(
        username=username,
        email=email,
        password=password,
    )
    token = _make_token(user)
    return JsonResponse({'token': token, 'username': user.username}, status=201)


@csrf_exempt
@require_http_methods(['POST'])
def login_view(request):
    """
    POST /api/auth/login/
    Body: { "username": "...", "password": "..." }
    Returns: { "token": "<jwt>", "username": "..." }
    """
    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON body.'}, status=400)

    username = body.get('username', '').strip()
    password = body.get('password', '')

    if not username or not password:
        return JsonResponse({'error': 'Username and password are required.'}, status=400)

    user = authenticate(request, username=username, password=password)
    if user is None:
        return JsonResponse({'error': 'Invalid username or password.'}, status=401)

    token = _make_token(user)
    return JsonResponse({'token': token, 'username': user.username}, status=200)


@require_http_methods(['POST'])
def logout_view(request):
    """POST /api/auth/logout/ — stateless JWT, just signal client to discard token."""
    return JsonResponse({'message': 'Logged out.'}, status=200)


@csrf_exempt
@require_http_methods(['POST'])
def forgot_password_view(request):
    """
    POST /api/auth/forgot-password/
    Body: { "email": "..." }
    Always returns 200 to prevent email enumeration.
    """
    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON body.'}, status=400)

    email = body.get('email', '').strip()

    if not email:
        return JsonResponse({'errors': {'email': 'Email is required.'}}, status=422)

    try:
        validate_email(email)
    except ValidationError:
        return JsonResponse({'errors': {'email': 'Enter a valid email address.'}}, status=422)

    # Always return success — don't reveal if email exists
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return JsonResponse({'message': 'If that email is registered, a reset link has been sent.'}, status=200)

    # Check email is configured before trying to send
    if not getattr(settings, 'EMAIL_HOST_USER', '') or settings.EMAIL_HOST_USER == 'your-email@gmail.com':
        logger.error('Email not configured. Set EMAIL_HOST_USER and EMAIL_HOST_PASSWORD in .env')
        return JsonResponse(
            {'error': 'Email service is not configured. Please contact the administrator.'},
            status=503,
        )

    reset_token = PasswordResetToken.create_for_user(user)
    frontend_url = settings.FRONTEND_URL.rstrip('/')
    reset_url = f'{frontend_url}/reset-password?token={reset_token.token}'

    try:
        send_mail(
            subject='AI Prompt Library — Password Reset',
            message=(
                f'Hi {user.username},\n\n'
                f'We received a request to reset your password.\n\n'
                f'Click the link below to set a new password (expires in 1 hour):\n\n'
                f'{reset_url}\n\n'
                f'If you did not request this, you can safely ignore this email.\n\n'
                f'— AI Prompt Library'
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )
    except Exception as exc:  # SMTPAuthenticationError, connection errors, etc.
        logger.error('Failed to send password reset email to %s: %s', email, exc)
        # Delete the unused token so it doesn\'t linger
        reset_token.delete()
        return JsonResponse(
            {'error': 'Could not send email. Check your email configuration in .env'},
            status=503,
        )

    return JsonResponse({'message': 'If that email is registered, a reset link has been sent.'}, status=200)


@csrf_exempt
@require_http_methods(['POST'])
def reset_password_view(request):
    """
    POST /api/auth/reset-password/
    Body: { "token": "...", "password": "...", "confirm_password": "..." }
    """
    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON body.'}, status=400)

    token_str = body.get('token', '').strip()
    password = body.get('password', '')
    confirm_password = body.get('confirm_password', '')

    errors = {}

    if not token_str:
        errors['token'] = 'Reset token is required.'

    if not password:
        errors['password'] = 'New password is required.'
    elif len(password) < 8:
        errors['password'] = 'Password must be at least 8 characters.'

    if not confirm_password:
        errors['confirm_password'] = 'Please confirm your new password.'
    elif password and confirm_password != password:
        errors['confirm_password'] = 'Passwords do not match.'

    if errors:
        return JsonResponse({'errors': errors}, status=422)

    try:
        reset_token = PasswordResetToken.objects.select_related('user').get(token=token_str)
    except PasswordResetToken.DoesNotExist:
        return JsonResponse({'error': 'Invalid or expired reset link. Please request a new one.'}, status=400)

    if not reset_token.is_valid():
        return JsonResponse({'error': 'This reset link has expired. Please request a new one.'}, status=400)

    # Set new password
    user = reset_token.user
    user.set_password(password)
    user.save()

    # Mark token used
    reset_token.used = True
    reset_token.save()

    return JsonResponse({'message': 'Password reset successfully. You can now log in.'}, status=200)


# ── Prompt endpoints ──────────────────────────────────────────────────────────

@csrf_exempt
@require_http_methods(['GET', 'POST'])
def prompt_list(request):
    """
    GET  /api/prompts/?tag=<name>  — list all prompts (optional tag filter)
    POST /api/prompts/             — create a new prompt (JWT required)
    """
    if request.method == 'GET':
        qs = Prompt.objects.prefetch_related('tags').all()

        tag_filter = request.GET.get('tag', '').strip().lower()
        if tag_filter:
            qs = qs.filter(tags__name=tag_filter)

        data = []
        for p in qs:
            data.append(_prompt_to_dict(p))

        return JsonResponse(data, safe=False, status=200)

    # POST — protected by JWT
    token = _get_token_from_request(request)
    if not token:
        return JsonResponse({'error': 'Authentication required.'}, status=401)
    try:
        _decode_token(token)
    except jwt.PyJWTError:
        return JsonResponse({'error': 'Invalid or expired token.'}, status=401)

    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON body.'}, status=400)

    errors, cleaned = validate_prompt_data(body)
    if errors:
        return JsonResponse({'errors': errors}, status=422)

    tag_names = cleaned.pop('tags', [])
    prompt = Prompt.objects.create(**cleaned)

    for name in tag_names:
        tag, _ = Tag.objects.get_or_create(name=name)
        prompt.tags.add(tag)

    return JsonResponse(_prompt_to_dict(prompt), status=201)


@require_http_methods(['GET'])
def prompt_detail(request, pk):
    """
    GET /api/prompts/<pk>/  — retrieve one prompt
    """
    try:
        prompt = Prompt.objects.prefetch_related('tags').get(pk=pk)
        
        # Increment the view count when successfully retrieved
        prompt.view_count += 1
        prompt.save(update_fields=['view_count'])
        
    except Prompt.DoesNotExist:
        return JsonResponse({'error': 'Prompt not found.'}, status=404)

    return JsonResponse(_prompt_to_dict(prompt), status=200)


@require_http_methods(['GET'])
def tag_list(request):
    """
    GET /api/tags/  — list all tags (for filter UI)
    """
    tags = list(Tag.objects.values_list('name', flat=True))
    return JsonResponse(tags, safe=False, status=200)
