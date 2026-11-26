// SPDX-License-Identifier: GPL-3.0-or-later

package mobile

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"pipe/internal/engine"
)

type measurementEngine struct{ *fakeEngine }

func (e *measurementEngine) MeasureRTT(_ context.Context, tier string) (time.Duration, bool, error) {
	switch tier {
	case "fast":
		return 11500 * time.Microsecond, false, nil
	case "stealth":
		return 0, true, nil
	default:
		return 0, false, errors.New("incomplete measurement")
	}
}

func TestUserMeasurementSurvivesHealthProbes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		raw, _ := sampleProfile(t)
		platform := &fakePlatform{statuses: make(chan string, 64)}
		var instance *measurementEngine
		b := bridge{newEngine: func(_ context.Context, options engine.Options) (clientEngine, error) {
			instance = &measurementEngine{fakeEngine: &fakeEngine{options: options}}
			return instance, nil
		}}
		if err := b.start(raw, `{}`, platform); err != nil {
			t.Fatal(err)
		}
		defer b.stop()
		synctest.Wait()
		if st := testStatus(t, b.statusJSON()); st.LatencyMs != nil || st.MeasurementAt != nil || len(st.Routes) != 0 {
			t.Fatalf("a health probe appeared as measured RTT: %+v", st)
		}
		b.testRoutes()
		instance.options.ObserveTraffic()
		synctest.Wait()
		st := testStatus(t, b.statusJSON())
		stealth := st.Routes["stealth"]
		if st.MeasurementAt == nil || st.LatencyMs == nil || *st.LatencyMs != 12 ||
			!stealth.OK || stealth.Ms != 0 || stealth.Via != "relay" || st.Routes["rescue"].OK {
			t.Fatalf("unexpected saved RTT outcomes: %+v", st)
		}
	})
}
