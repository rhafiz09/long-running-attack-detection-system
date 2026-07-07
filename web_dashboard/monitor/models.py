from django.db import models


class BaseFirewallLog(models.Model):
    """
    Abstract Django ORM Model for Cybersecurity Firewall Logs.
    Maps to existing PostgreSQL tables created and owned by FastAPI / SQLAlchemy.
    """
    id = models.AutoField(primary_key=True)
    log_date = models.DateTimeField(null=True, blank=True, db_index=True)
    ip_origin = models.CharField(max_length=50, null=True, blank=True, db_index=True)
    ip_impacted = models.CharField(max_length=50, null=True, blank=True, db_index=True)
    port_impacted = models.IntegerField(null=True, blank=True, db_index=True)
    zone_origin = models.CharField(max_length=50, null=True, blank=True, db_index=True)
    zone_impacted = models.CharField(max_length=50, null=True, blank=True, db_index=True)
    log_source = models.CharField(max_length=100, null=True, blank=True, db_index=True)
    additional_data = models.JSONField(default=dict, null=True, blank=True)

    class Meta:
        abstract = True


class PaloAltoLog(BaseFirewallLog):
    """
    Django ORM model representing Palo Alto firewall logs.
    Set managed = False so Django never runs migrations or alters this table.
    """
    class Meta:
        managed = False
        db_table = "palo_alto_logs"
        ordering = ["-log_date"]
        verbose_name = "Palo Alto Log"
        verbose_name_plural = "Palo Alto Logs"


class FortinetLog(BaseFirewallLog):
    """
    Django ORM model representing Fortinet firewall logs.
    """
    class Meta:
        managed = False
        db_table = "fortinet_logs"
        ordering = ["-log_date"]
        verbose_name = "Fortinet Log"
        verbose_name_plural = "Fortinet Logs"


class FortiwafLog(BaseFirewallLog):
    """
    Django ORM model representing FortiWAF Web Application Firewall logs.
    """
    class Meta:
        managed = False
        db_table = "fortiwaf_logs"
        ordering = ["-log_date"]
        verbose_name = "FortiWAF Log"
        verbose_name_plural = "FortiWAF Logs"
