
### Hello!

```yaml
type: OPAPolicy
mesh: default
name: opa-1
selectors:
- match:
    kuma.io/service: '*'
conf:
  agentConfig:
    inlineString: | 
      services:
        acmecorp:
          url: https://example.com/control-plane-api/v1
          credentials:
            bearer:
              token: "hMLfg2XwFsdng3TqgsFyg2Lwi2Xyg2FwECzyi2XwFszxgsXsECdqi2zs"
      discovery:
        name: example
        resource: /configuration/example/discovery
    fdsafdsa: test
```

## BYE
{% endnavtab %}
{% endnavtabs %}





