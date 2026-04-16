from django.contrib import admin
from .models import Prompt, Tag


@admin.register(Tag)
class TagAdmin(admin.ModelAdmin):
    list_display = ('id', 'name')
    search_fields = ('name',)


@admin.register(Prompt)
class PromptAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'complexity', 'get_tags', 'created_at')
    list_filter = ('complexity', 'tags')
    search_fields = ('title', 'content')
    ordering = ('-created_at',)
    filter_horizontal = ('tags',)

    @admin.display(description='Tags')
    def get_tags(self, obj):
        return ', '.join(obj.tags.values_list('name', flat=True))
