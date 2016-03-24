# Fernet2 and PWFernet Spec Sheet

Inspired by [link](http://tomdoc.org),
It is **not** a preprocessor,

## Fernet2


n *how people work with CSS* —


### Format

 example:

```css
/*
A button suitable for giving stars to someone.

:hover             - Subtle hover highlight.
.stars-given       - A highlight indicating you've already given a star.
.stars-given:hover - Subtle hover highlight on top of stars-given styling.
.disabled          - Dims the button to indicate it cannot be used.

Styleguide 2.1.3.
*/
a.button.star{
  ...
}
a.button.star.stars-given{
  ...
}
a.button.star.disabled{
  ...
}
```



**Experimental** 


### The modifiers section

If the UI element you are documenting has multiple states or styles depending on added classes or pseudo-classes, you should document them in the modifiers section.

```scss
// :hover             - Subtle hover highlight.
// .stars-given       - A highlight indicating you've already given a star.
// .stars-given:hover - Subtle hover highlight on top of stars-given styling.
// .disabled          - Dims the button to indicate it cannot be used.
```

### The styleguide section

If the UI element you are documenting has an example in the styleguide, you should reference it using the "Styleguide [ref]" syntax.


    1. Buttons
      1.1 Form Buttons
        1.1.1 Generic form button
        1.1.2 Special form button
      1.2 Social buttons
      1.3 Miscelaneous buttons
    2. Form elements
      2.1 Text fields
      2.2 Radio and checkboxes
    3. Text styling
    4. Tables
      4.1 Number tables
      4.2 Diagram tables

