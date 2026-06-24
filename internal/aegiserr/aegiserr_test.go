package aegiserr

import (
	"encoding/json"
	"testing"
)

func TestCapDeniedVerboseVsMinimal(t *testing.T) {
	verbose := CapDenied("sonarqube.scan", "default", "code-review", "verbose")
	var v map[string]any
	_ = json.Unmarshal([]byte(verbose.JSON()), &v)
	if v["code"] != "AEGIS_CAP_DENIED" || v["capability"] != "sonarqube.scan" {
		t.Fatalf("missing stable fields: %v", v)
	}
	if v["required_profile"] != "code-review" {
		t.Errorf("verbose must disclose required_profile")
	}

	minimal := CapDenied("sonarqube.scan", "default", "code-review", "minimal")
	var v2 map[string]any
	_ = json.Unmarshal([]byte(minimal.JSON()), &v2)
	if _, present := v2["required_profile"]; present {
		t.Errorf("minimal must NOT disclose required_profile")
	}
	if v2["capability"] != "sonarqube.scan" {
		t.Errorf("capability is always present")
	}
}

func TestPendingApproval(t *testing.T) {
	p := PendingApproval("apr_1", "default", "deploy")
	var v map[string]any
	_ = json.Unmarshal([]byte(p.JSON()), &v)
	if v["code"] != "AEGIS_PENDING_APPROVAL" || v["approval_id"] != "apr_1" {
		t.Fatalf("bad pending payload: %v", v)
	}
}

func TestResourceDenied(t *testing.T) {
	var v map[string]any
	_ = json.Unmarshal([]byte(ResourceDenied("file:///etc/passwd", "default").JSON()), &v)
	if v["code"] != string(CodeResourceDenied) || v["uri"] != "file:///etc/passwd" {
		t.Fatalf("bad resource-denied payload: %v", v)
	}
	if v["active_profile"] != "default" {
		t.Errorf("active_profile must be present")
	}
}

func TestProfileUnknown(t *testing.T) {
	var v map[string]any
	_ = json.Unmarshal([]byte(ProfileUnknown("ghost").JSON()), &v)
	if v["code"] != string(CodeProfileUnknown) || v["requested_profile"] != "ghost" {
		t.Fatalf("bad profile-unknown payload: %v", v)
	}
}

func TestMapExposesFields(t *testing.T) {
	m := CapDenied("x.y", "default", "", "minimal").Map()
	if m["code"] != string(CodeCapDenied) {
		t.Errorf("Map() must expose the raw fields")
	}
}
