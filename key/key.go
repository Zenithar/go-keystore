package key

// Key contract for key information holder
type Key interface {
	ID() string
	Algorithm() string
	HasPrivate() bool
	HasPublic() bool
	Public() Key
}
