import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ImageContComponent } from './image-cont.component';

describe('ImageContComponent', () => {
  let component: ImageContComponent;
  let fixture: ComponentFixture<ImageContComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ImageContComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(ImageContComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
