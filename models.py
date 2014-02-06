import os


from django.db import models
from django.contrib.auth.models import User
from django.conf import settings

class security_report(models.Model):
	id=models.AutoField(primary_key=True)
	received=models.DateTimeField(auto_now_add=True, blank=True)
	csp_report=models.CharField(max_length=1000)
	blocked_uri=models.CharField()
	column_number=models.IntegerField()
	document_uri=models.CharField()
	line_number = models.IntegerField()
	original_policy= models.CharField()
	referrer = models.CharField()
	status_code = models.IntegerField()
	violated_directive = models.CharField()
	source_file = models.CharField()
	script_sample = models.CharField()

	class Meta:
		app_label = "events"

	def __unicode__(self):
		return  '%s %s %s %s %s %s %s %s %s %s %s %s %s' % (self.id, self.received, self.csp_report, self.blocked_uri, self.column_number,
		self.document_uri, self.line_number, self.original_policy, self.referrer, self.status_code, self.violated_directive,
		self.source_file, self.script_sample)

