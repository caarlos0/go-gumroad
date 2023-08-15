# go-gumroad


[![Build Status](https://img.shields.io/github/actions/workflow/status/caarlos0/go-gumroad/build.yml?branch=main&style=for-the-badge)](https://github.com/caarlos0/go-gumroad/actions?workflow=build)
[![Coverage Status](https://img.shields.io/codecov/c/gh/caarlos0/go-gumroad.svg?logo=codecov&style=for-the-badge)](https://codecov.io/gh/caarlos0/go-gumroad)
[![](http://img.shields.io/badge/godoc-reference-5272B4.svg?style=for-the-badge)](https://pkg.go.dev/github.com/caarlos0/go-gumroad)

Easily check licenses against Gumroad's API.

## Usage

```golang
package main

import "github.com/caarlos0/go-gumroad"

func check(key string) error {
	prod, err := gumroad.NewProduct("my-product-permalink")
	if err != nil {
		return err
	}
	return prod.Verify(key)
}
```
