package audit

import "time"

// Options 控制 Open 的行为。
type Options struct {
	// Clock 返回“当前时间”；为 nil 时使用 time.Now。
	// 注入时钟可让保留期判定在测试中完全确定、可解释。
	Clock func() time.Time
}

func (o Options) now() time.Time {
	if o.Clock != nil {
		return o.Clock()
	}
	return time.Now()
}
