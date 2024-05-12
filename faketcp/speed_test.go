package faketcp_test

import (
	"testing"
	"time"

	"github.com/lysShub/fatcp/faketcp"
	"github.com/stretchr/testify/require"
)

func Test_Speed(t *testing.T) {

	{
		s := faketcp.NewSpeed(1024)
		v := s.Speed()
		require.Zero(t, v)
	}

	{
		s := faketcp.NewSpeed(1024)
		s.Add(1)
		v := s.Speed()
		require.Zero(t, v)
	}

	{
		s := faketcp.NewSpeed(1024)
		s.Add(1)
		time.Sleep(time.Millisecond * 990)
		s.Add(1024)
		v := s.Speed()
		require.Greater(t, v, float64(1000))
		require.Less(t, v, float64(1048))
	}

	{
		s := faketcp.NewSpeed(1024)
		time.Sleep(time.Second)

		s.Add(1)
		time.Sleep(time.Millisecond * 990)
		s.Add(1024)
		v := s.Speed()
		require.Greater(t, v, float64(1000))
		require.Less(t, v, float64(1048))
	}

	{
		s := faketcp.NewSpeed(1024)
		time.Sleep(time.Second)

		s.Add(1)
		time.Sleep(time.Millisecond * 990)
		s.Add(1024)
		v1 := s.Speed() // will upgrade
		require.Greater(t, v1, float64(1000))
		require.Less(t, v1, float64(1048))

		s.Add(1)
		time.Sleep(time.Millisecond * 1100)
		s.Add(1)
		v2 := s.Speed()
		require.Equal(t, v1, v2)
	}

	{
		s := faketcp.NewSpeed(1024)
		time.Sleep(time.Second)

		s.Add(1)
		time.Sleep(time.Millisecond * 990)
		s.Add(1024)
		v1 := s.Speed() // will upgrade
		require.Greater(t, v1, float64(1000))
		require.Less(t, v1, float64(1048))

		s.Add(1)
		time.Sleep(time.Millisecond * 1100)
		s.Add(1024)
		v2 := s.Speed() // will upgrade
		require.Greater(t, v2, float64(900))
		require.Less(t, v2, float64(1048))
	}
}
