import secrets
from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone


class Tag(models.Model):
    """A simple label that can be attached to many prompts (M2M)."""
    name = models.CharField(max_length=64, unique=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name


class Prompt(models.Model):
    title = models.CharField(max_length=255)
    content = models.TextField()
    complexity = models.IntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(10)]
    )
    tags = models.ManyToManyField(Tag, blank=True, related_name='prompts')
    created_at = models.DateTimeField(auto_now_add=True)
    view_count = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.title


class PasswordResetToken(models.Model):
    """Single-use, time-limited token for password reset emails."""
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='reset_tokens',
    )
    token = models.CharField(max_length=64, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    used = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']

    @classmethod
    def create_for_user(cls, user):
        """Delete old tokens for user, generate a fresh one."""
        cls.objects.filter(user=user).delete()
        return cls.objects.create(user=user, token=secrets.token_urlsafe(48))

    def is_valid(self):
        """Valid if unused and created less than 1 hour ago."""
        age = (timezone.now() - self.created_at).total_seconds()
        return not self.used and age < 3600

    def __str__(self):
        return f'ResetToken({self.user.username})'
