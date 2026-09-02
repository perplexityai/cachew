package admission

import "testing"

func BenchmarkAdmissionAcquireRelease(b *testing.B) {
	limiter, err := New(Config{Limit: 1024, Reserved: 8})
	if err != nil {
		b.Fatal(err)
	}
	for _, benchmark := range []struct {
		name      string
		protected bool
	}{
		{name: "Normal"},
		{name: "Protected", protected: true},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if !limiter.acquire(benchmark.protected) {
						b.Fatal("admission unexpectedly rejected below capacity")
					}
					limiter.release(benchmark.protected)
				}
			})
		})
	}
}
