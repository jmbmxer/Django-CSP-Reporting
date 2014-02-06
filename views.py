from security_report.models import security_report
from django.utils import simplejson
from django.http import HttpResponse, HttpRequest
from django.views.decorators.csrf import csrf_exempt, csrf_protect
import json

@csrf_exempt
def secreport(request):

	if request.method == "POST":
		json_data = simplejson.loads(request.raw_post_data)
		try:
			data = json_data['csp-report']
			document_uri = data['document-uri']
			referrer = data['referrer']
			blocked_uri = data['blocked-uri']
			violated_directive = data['violated-directive']
			source_file = data['source-file']
			script_sample = data['script-sample']

			b = security_report(csp_report = data, document_uri = document_uri, referrer = referrer,
			blocked_uri=blocked_uri, violated_directive = violated_directive, source_file=source_file, script_sample=script_sample)
			#b = security_report.objects.all()
			b.save()
			return HttpResponse("saved")
		except Exception as e:
			print '%s (%s)' (e.message, type(e))
	else:
		return HttpResponse("not a post request")




